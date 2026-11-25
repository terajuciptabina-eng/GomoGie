const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
});

const text = (value, max) => typeof value === "string" && value.trim().length > 0 && value.trim().length <= max;
const b64url = (bytes) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};
const fromB64url = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(value => value.trim()).filter(Boolean);
  if (!origin || !allowed.includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
}

async function passwordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  return "pbkdf2-sha256$100000$" + b64url(salt) + "$" + b64url(new Uint8Array(bits));
}

async function passwordVerify(password, stored) {
  try {
    const [scheme, rounds, saltText, hashText] = stored.split("$");
    if (scheme !== "pbkdf2-sha256" || Number(rounds) !== 100000) return false;
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64url(saltText), iterations: Number(rounds) }, key, 256);
    const actual = new Uint8Array(bits);
    const expected = fromB64url(hashText);
    if (actual.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch { return false; }
}

async function signToken(user, env) {
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be configured with at least 32 characters");
  const header = b64url(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(encoder.encode(JSON.stringify({ sub: user.id, username: user.username, iat: now, exp: now + 900 })));
  const input = header + "." + payload;
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(input));
  return input + "." + b64url(new Uint8Array(signature));
}

async function authenticate(request, env) {
  const value = request.headers.get("Authorization") || "";
  const match = value.match(/^Bearer\s+(.+)$/i);
  if (!match || !env.JWT_SECRET || env.JWT_SECRET.length < 32) return null;
  try {
    const parts = match[1].split(".");
    if (parts.length !== 3 || parts.some(part => !part)) return null;
    const [head, body, signature] = parts;
    const header = JSON.parse(decoder.decode(fromB64url(head)));
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;
    const key = await crypto.subtle.importKey("raw", encoder.encode(env.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, fromB64url(signature), encoder.encode(head + "." + body));
    if (!valid) return null;
    const payload = JSON.parse(decoder.decode(fromB64url(body)));
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.sub !== "string" || !payload.sub || !Number.isInteger(payload.exp) ||
        !Number.isInteger(payload.iat) || payload.exp <= now || payload.iat > now + 60 ||
        payload.exp - payload.iat > 900) return null;
    const account = await env.DB.prepare("SELECT status FROM users WHERE id = ?").bind(payload.sub).first();
    if (!account || account.status !== "active") return null;
    return payload;
  } catch { return null; }
}

async function readJson(request, maxBytes = 65536) {
  try {
    const declaredLength = Number(request.headers.get("content-length") || 0);
    if (declaredLength > maxBytes) return null;
    const raw = await request.text();
    if (encoder.encode(raw).byteLength > maxBytes) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

function uuid() { return crypto.randomUUID(); }

const IMAGE_LIMIT = 8 * 1024 * 1024;
function detectImageType(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  if (bytes.length >= 12 && String.fromCharCode(...bytes.slice(0,4)) === "RIFF" && String.fromCharCode(...bytes.slice(8,12)) === "WEBP") return "image/webp";
  if (bytes.length >= 6 && ["GIF87a","GIF89a"].includes(String.fromCharCode(...bytes.slice(0,6)))) return "image/gif";
  return null;
}
function mediaUrl(id) { return "https://gomogie-api.terajucibina.workers.dev/v1/media/" + encodeURIComponent(id); }

async function route(request, env) {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;

  if (path === "/health/live" && method === "GET") {
    return json({ status: "ok", service: "gomogie-api", runtime: "cloudflare-workers" });
  }
  if (path === "/health/ready" && method === "GET") {
    try {
      await env.DB.prepare("SELECT 1 AS ready").first();
      return json({ status: "ready", database: "connected" });
    } catch {
      return json({ status: "not_ready", database: "unavailable" }, 503);
    }
  }

  if (path === "/v1/auth/register" && method === "POST") {
    if (env.ALLOW_REGISTRATION !== "true") {
      return json({ error: "registration_closed", message: "Pendaftaran awam belum dibuka." }, 403);
    }
    const input = await readJson(request);
    if (!input || !text(input.email, 254) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email.trim()) ||
        !text(input.username, 24) || !/^[a-zA-Z0-9_]{3,24}$/.test(input.username.trim()) ||
        typeof input.password !== "string" || input.password.length < 9 || input.password.length > 128 ||
        !text(input.displayName, 60)) {
      return json({ error: "validation_error", message: "Email, username, kata laluan (9–128 aksara) dan nama paparan diperlukan." }, 400);
    }
    const email = input.email.trim().toLowerCase();
    const username = input.username.trim().toLowerCase();
    const exists = await env.DB.prepare("SELECT id FROM users WHERE email = ? OR username = ?").bind(email, username).first();
    if (exists) return json({ error: "account_exists", message: "Email atau username telah digunakan." }, 409);

    const id = uuid();
    const now = new Date().toISOString();
    const hash = await passwordHash(input.password);
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users (id,email,username,password_hash,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)")
          .bind(id, email, username, hash, "active", now, now),
        env.DB.prepare("INSERT INTO profiles (user_id,display_name,bio,created_at,updated_at) VALUES (?,?,?,?,?)")
          .bind(id, input.displayName.trim(), "", now, now)
      ]);
    } catch (error) {
      return json({ error: "registration_failed", message: "Pendaftaran gagal. Semak email dan username." }, 409);
    }
    const user = { id, email, username };
    return json({ user, profile: { user_id: id, display_name: input.displayName.trim(), bio: "" }, accessToken: await signToken(user, env), tokenType: "Bearer", expiresIn: 900 }, 201);
  }

  if (path === "/v1/auth/login" && method === "POST") {
    const input = await readJson(request);
    if (!input || !text(input.login, 254) || typeof input.password !== "string" || input.password.length > 128) {
      return json({ error: "validation_error" }, 400);
    }
    const user = await env.DB.prepare("SELECT id,email,username,password_hash,status FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE")
      .bind(input.login.trim(), input.login.trim()).first();
    if (!user || user.status !== "active" || !(await passwordVerify(input.password, user.password_hash))) {
      return json({ error: "invalid_credentials", message: "Maklumat log masuk tidak tepat." }, 401);
    }
    return json({ user: { id: user.id, email: user.email, username: user.username }, accessToken: await signToken(user, env), tokenType: "Bearer", expiresIn: 900 });
  }

  const publicCommentsRead = method === "GET" && /^\/v1\/posts\/[0-9a-f-]+\/comments$/i.test(path);
  const publicMediaRead = method === "GET" && /^\/v1\/media\/[0-9a-f-]+$/i.test(path);
  const needsAuth = path === "/v1/auth/me" || (path.startsWith("/v1/posts") && !publicCommentsRead) || (path.startsWith("/v1/media") && !publicMediaRead) || path.startsWith("/v1/users/") || path.startsWith("/v1/notifications") || path.startsWith("/v1/conversations");
  const auth = needsAuth ? await authenticate(request, env) : null;
  if (needsAuth && !auth) return json({ error: "unauthorized", message: "Sila log masuk semula." }, 401);

  const mediaReadMatch = path.match(/^\/v1\/media\/([0-9a-f-]+)$/i);
  if (mediaReadMatch && method === "GET") {
    if (!env.MEDIA_BUCKET) return json({ error: "media_storage_unavailable" }, 503);
    const asset = await env.DB.prepare("SELECT object_key,mime_type,size_bytes FROM gomogie_media_assets WHERE id=? AND status='ready'").bind(mediaReadMatch[1]).first();
    if (!asset) return json({ error: "media_not_found" }, 404);
    const object = await env.MEDIA_BUCKET.get(asset.object_key);
    if (!object) return json({ error: "media_not_found" }, 404);
    return new Response(object.body, { headers: { "content-type": asset.mime_type, "content-length": String(asset.size_bytes), "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff" } });
  }

  if (path === "/v1/media" && method === "POST") {
    const declaredLength = Number(request.headers.get("content-length") || 0);
    if (declaredLength > IMAGE_LIMIT + 65536) return json({ error: "file_size_invalid", message: "Saiz gambar maksimum ialah 8 MB." }, 413);
    if (!env.MEDIA_BUCKET) return json({ error: "media_storage_unavailable", message: "Cloudflare R2 belum dihubungkan kepada Worker." }, 503);
    const form = await request.formData();
    const file = form.get("file"), purpose = form.get("purpose");
    if (!(file instanceof File) || !["avatar","cover","post"].includes(purpose)) return json({ error: "validation_error", message: "Fail gambar dan tujuan upload diperlukan." }, 400);
    if (!file.size || file.size > IMAGE_LIMIT) return json({ error: "file_size_invalid", message: "Saiz gambar maksimum ialah 8 MB." }, 413);
    const bytes = new Uint8Array(await file.arrayBuffer());
    const detected = detectImageType(bytes);
    if (!detected || detected !== file.type) return json({ error: "unsupported_image", message: "Format yang disokong: JPEG, PNG, WebP dan GIF." }, 415);
    const id = uuid(), now = new Date().toISOString();
    const extension = ({ "image/jpeg":"jpg", "image/png":"png", "image/webp":"webp", "image/gif":"gif" })[detected];
    const key = "users/" + auth.sub + "/" + purpose + "/" + id + "." + extension;
    await env.MEDIA_BUCKET.put(key, bytes, { httpMetadata: { contentType: detected, cacheControl: "public, max-age=31536000, immutable" }, customMetadata: { ownerId: auth.sub, purpose } });
    try {
      const statements = [env.DB.prepare("INSERT INTO gomogie_media_assets (id,owner_id,purpose,object_key,mime_type,size_bytes,status,created_at) VALUES (?,?,?,?,?,?,?,?)").bind(id, auth.sub, purpose, key, detected, file.size, "ready", now)];
      if (purpose === "avatar" || purpose === "cover") {
        const column = purpose === "avatar" ? "avatar_url" : "cover_url";
        statements.push(env.DB.prepare("UPDATE profiles SET " + column + "=?,updated_at=? WHERE user_id=?").bind(mediaUrl(id), now, auth.sub));
      }
      await env.DB.batch(statements);
    } catch (error) { await env.MEDIA_BUCKET.delete(key); throw error; }
    return json({ media: { id, purpose, url: mediaUrl(id), mimeType: detected, size: file.size, createdAt: now } }, 201);
  }

  if (path === "/v1/auth/me" && method === "GET") {
    const row = await env.DB.prepare("SELECT u.id,u.email,u.username,u.status,u.created_at,p.display_name,p.bio,p.avatar_url,p.cover_url,p.website,p.location,p.is_private FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.id=?")
      .bind(auth.sub).first();
    if (!row || row.status !== "active") return json({ error: "user_not_found" }, 404);
    return json({ user: { id: row.id, email: row.email, username: row.username, createdAt: row.created_at }, profile: { displayName: row.display_name, bio: row.bio, avatarUrl: row.avatar_url, coverUrl: row.cover_url, website: row.website, location: row.location, isPrivate: Boolean(row.is_private) } });
  }

  if (path === "/v1/auth/me" && method === "PUT") {
    const input = await readJson(request);
    if (!input || !text(input.displayName, 60) ||
        (input.bio !== undefined && typeof input.bio !== "string") ||
        (input.location !== undefined && typeof input.location !== "string") ||
        (input.website !== undefined && typeof input.website !== "string") ||
        (input.avatarUrl !== undefined && typeof input.avatarUrl !== "string") ||
        (input.coverUrl !== undefined && typeof input.coverUrl !== "string")) {
      return json({ error: "validation_error", message: "Maklumat profil tidak sah." }, 400);
    }
    const fields = {
      bio: (input.bio || "").trim(),
      location: (input.location || "").trim(),
      website: (input.website || "").trim(),
      avatarUrl: (input.avatarUrl || "").trim(),
      coverUrl: (input.coverUrl || "").trim()
    };
    if (fields.bio.length > 160 || fields.location.length > 80 || fields.website.length > 120 ||
        fields.avatarUrl.length > 2048 || fields.coverUrl.length > 2048) {
      return json({ error: "validation_error", message: "Satu atau lebih medan melebihi had aksara." }, 400);
    }
    for (const value of [fields.website, fields.avatarUrl, fields.coverUrl]) {
      if (value && !/^https:\/\//i.test(value)) {
        return json({ error: "invalid_url", message: "Pautan profil mestilah bermula dengan https://." }, 400);
      }
    }
    const now = new Date().toISOString();
    await env.DB.prepare(
      "UPDATE profiles SET display_name=?,bio=?,location=?,website=?,avatar_url=COALESCE(?,avatar_url),cover_url=COALESCE(?,cover_url),updated_at=? WHERE user_id=?"
    ).bind(input.displayName.trim(), fields.bio, fields.location, fields.website,
      fields.avatarUrl || null, fields.coverUrl || null, now, auth.sub).run();
    const row = await env.DB.prepare(
      "SELECT u.id,u.email,u.username,u.created_at,p.display_name,p.bio,p.avatar_url,p.cover_url,p.website,p.location,p.is_private FROM users u JOIN profiles p ON p.user_id=u.id WHERE u.id=?"
    ).bind(auth.sub).first();
    if (!row) return json({ error: "profile_not_found" }, 404);
    return json({ user: { id: row.id, email: row.email, username: row.username, createdAt: row.created_at },
      profile: { displayName: row.display_name, bio: row.bio, avatarUrl: row.avatar_url,
        coverUrl: row.cover_url, website: row.website, location: row.location, isPrivate: Boolean(row.is_private) } });
  }

  if (path === "/v1/notifications" && method === "GET") {
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 30)));
    const rows = await env.DB.prepare(
      "SELECT n.id,n.type,n.entity_id,n.is_read,n.created_at,n.actor_id,u.username,p.display_name,p.avatar_url FROM notifications n LEFT JOIN users u ON u.id=n.actor_id LEFT JOIN profiles p ON p.user_id=n.actor_id WHERE n.recipient_id=? ORDER BY n.created_at DESC LIMIT ?"
    ).bind(auth.sub, limit).all();
    const unread = await env.DB.prepare("SELECT COUNT(*) AS count FROM notifications WHERE recipient_id=? AND is_read=0").bind(auth.sub).first();
    return json({ items: (rows.results || []).map(row => ({ id: row.id, type: row.type, entityId: row.entity_id, isRead: Boolean(row.is_read), createdAt: row.created_at, actor: row.actor_id ? { id: row.actor_id, username: row.username, displayName: row.display_name, avatarUrl: row.avatar_url } : null })), unreadCount: Number(unread?.count || 0) });
  }
  const notificationReadMatch = path.match(/^\/v1\/notifications\/([0-9a-f-]+)\/read$/i);
  if (notificationReadMatch && method === "PATCH") {
    const result = await env.DB.prepare("UPDATE notifications SET is_read=1 WHERE id=? AND recipient_id=?").bind(notificationReadMatch[1], auth.sub).run();
    if (!result.meta?.changes) return json({ error: "notification_not_found" }, 404);
    return json({ updated: true });
  }
  if (path === "/v1/notifications/read-all" && method === "PATCH") {
    const result = await env.DB.prepare("UPDATE notifications SET is_read=1 WHERE recipient_id=? AND is_read=0").bind(auth.sub).run();
    return json({ updated: Number(result.meta?.changes || 0) });
  }
  if (path === "/v1/feed" && method === "GET") {
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 20)));
    const rows = await env.DB.prepare(
      "SELECT p.id,p.user_id,p.content,p.visibility,p.created_at,p.comments_enabled,u.username,pr.display_name,pr.avatar_url,pr.cover_url," +
      "(SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) AS reaction_count," +
      "(SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id AND c.status='published') AS comment_count,ma.id AS media_id " +
      "FROM posts p JOIN users u ON u.id=p.user_id LEFT JOIN profiles pr ON pr.user_id=p.user_id " +
      "LEFT JOIN gomogie_post_media pm ON pm.post_id=p.id LEFT JOIN gomogie_media_assets ma ON ma.id=pm.media_id AND ma.status='ready' " +
      "WHERE p.status='published' AND p.visibility='public' ORDER BY p.created_at DESC LIMIT ?"
    ).bind(limit).all();
    return json({ items: (rows.results || []).map(row => ({ id: row.id, content: row.content, visibility: row.visibility, createdAt: row.created_at, commentsEnabled: Boolean(row.comments_enabled), author: { id: row.user_id, username: row.username, displayName: row.display_name, avatarUrl: row.avatar_url, coverUrl: row.cover_url }, mediaType: row.media_id ? "image" : "text", mediaUrl: row.media_id ? mediaUrl(row.media_id) : "", reactionCount: row.reaction_count, commentCount: row.comment_count })) });
  }

  if (path === "/v1/posts" && method === "POST") {
    const input = await readJson(request);
    if (!input || typeof input.content !== "string" || input.content.length > 5000 ||
        (!input.content.trim() && !text(input.mediaId, 64))) return json({ error: "validation_error", message: "Tulis kandungan atau lampirkan gambar." }, 400);
    const visibility = ["public", "followers", "private"].includes(input.visibility) ? input.visibility : "public";
    const id = uuid(), now = new Date().toISOString();
    let media = null;
    if (input.mediaId) {
      media = await env.DB.prepare("SELECT id FROM gomogie_media_assets WHERE id=? AND owner_id=? AND purpose='post' AND status='ready'").bind(input.mediaId, auth.sub).first();
      if (!media) return json({ error: "media_not_found", message: "Gambar post tidak ditemui atau bukan milik akaun ini." }, 404);
    }
    await env.DB.prepare("INSERT INTO posts (id,user_id,content,visibility,status,comments_enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)").bind(id, auth.sub, input.content.trim(), visibility, "published", input.commentsEnabled === false ? 0 : 1, now, now).run();
    if (media) await env.DB.prepare("INSERT INTO gomogie_post_media (post_id,media_id,position,created_at) VALUES (?,?,?,?)").bind(id, media.id, 0, now).run();
    return json({ post: { id, userId: auth.sub, content: input.content.trim(), visibility, status: "published", mediaType: media ? "image" : "text", mediaUrl: media ? mediaUrl(media.id) : "", createdAt: now } }, 201);
  }

  const reactionMatch = path.match(/^\/v1\/posts\/([0-9a-f-]+)\/reactions$/i);
  if (reactionMatch && method === "POST") {
    const input = await readJson(request) || {};
    const type = input.type || "like";
    if (!["like", "love", "haha", "wow", "sad", "angry"].includes(type)) return json({ error: "invalid_reaction" }, 400);
    const post = await env.DB.prepare("SELECT id,user_id FROM posts WHERE id=? AND status='published'").bind(reactionMatch[1]).first();
    if (!post) return json({ error: "post_not_found" }, 404);
    const previous = await env.DB.prepare("SELECT reaction_type FROM reactions WHERE user_id=? AND post_id=?").bind(auth.sub, reactionMatch[1]).first();
    await env.DB.prepare("INSERT INTO reactions (user_id,post_id,reaction_type) VALUES (?,?,?) ON CONFLICT(user_id,post_id) DO UPDATE SET reaction_type=excluded.reaction_type")
      .bind(auth.sub, reactionMatch[1], type).run();
    if (!previous && post.user_id !== auth.sub) {
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)")
        .bind(uuid(), post.user_id, auth.sub, "reaction", reactionMatch[1], new Date().toISOString()).run();
    }
    return json({ reaction: { postId: reactionMatch[1], type } });
  }
  if (reactionMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM reactions WHERE user_id=? AND post_id=?").bind(auth.sub, reactionMatch[1]).run();
    return new Response(null, { status: 204 });
  }

  const commentMatch = path.match(/^\/v1\/posts\/([0-9a-f-]+)\/comments$/i);
  if (commentMatch && method === "GET") {
    const post = await env.DB.prepare("SELECT id,visibility,status FROM posts WHERE id=?").bind(commentMatch[1]).first();
    if (!post || post.status !== "published" || post.visibility !== "public") return json({ error: "post_not_found" }, 404);
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const rows = await env.DB.prepare(
      "SELECT c.id,c.post_id,c.user_id,c.parent_id,c.content,c.created_at,u.username,p.display_name,p.avatar_url FROM comments c JOIN users u ON u.id=c.user_id LEFT JOIN profiles p ON p.user_id=c.user_id WHERE c.post_id=? AND c.status='published' ORDER BY c.created_at ASC LIMIT ?"
    ).bind(commentMatch[1], limit).all();
    return json({ items: (rows.results || []).map(row => ({ id: row.id, postId: row.post_id, userId: row.user_id, parentId: row.parent_id, content: row.content, createdAt: row.created_at, author: { username: row.username, displayName: row.display_name, avatarUrl: row.avatar_url } })) });
  }
  if (commentMatch && method === "POST") {
    const input = await readJson(request);
    if (!input || !text(input.content, 2000)) return json({ error: "validation_error" }, 400);
    const post = await env.DB.prepare("SELECT id,comments_enabled FROM posts WHERE id=? AND status='published'").bind(commentMatch[1]).first();
    if (!post) return json({ error: "post_not_found" }, 404);
    if (!post.comments_enabled) return json({ error: "comments_disabled" }, 403);
    const id = uuid(), now = new Date().toISOString();
    await env.DB.prepare("INSERT INTO comments (id,post_id,user_id,parent_id,content,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
      .bind(id, commentMatch[1], auth.sub, input.parentId || null, input.content.trim(), "published", now, now).run();
    const owner = await env.DB.prepare("SELECT user_id FROM posts WHERE id=?").bind(commentMatch[1]).first();
    if (owner && owner.user_id !== auth.sub) {
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)")
        .bind(uuid(), owner.user_id, auth.sub, "comment", commentMatch[1], now).run();
    }
    return json({ comment: { id, postId: commentMatch[1], userId: auth.sub, content: input.content.trim(), createdAt: now } }, 201);
  }

  const followMatch = path.match(/^\/v1\/users\/([a-zA-Z0-9_]{3,24})\/follow$/);
  if (followMatch && method === "POST") {
    const target = await env.DB.prepare("SELECT u.id,p.is_private FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.username=? COLLATE NOCASE AND u.status='active'")
      .bind(followMatch[1]).first();
    if (!target) return json({ error: "user_not_found" }, 404);
    if (target.id === auth.sub) return json({ error: "cannot_follow_self" }, 400);
    const status = target.is_private ? "pending" : "accepted";
    const existingFollow = await env.DB.prepare("SELECT status FROM follows WHERE follower_id=? AND following_id=?").bind(auth.sub, target.id).first();
    await env.DB.prepare("INSERT INTO follows (follower_id,following_id,status) VALUES (?,?,?) ON CONFLICT(follower_id,following_id) DO UPDATE SET status=excluded.status")
      .bind(auth.sub, target.id, status).run();
    if (!existingFollow && status === "accepted") {
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)")
        .bind(uuid(), target.id, auth.sub, "follow", auth.sub, new Date().toISOString()).run();
    }
    return json({ following: true, status });
  }
  if (followMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM follows WHERE follower_id=? AND following_id=(SELECT id FROM users WHERE username=? COLLATE NOCASE)")
      .bind(auth.sub, followMatch[1]).run();
    return new Response(null, { status: 204 });
  }


  if (path === "/v1/conversations" && method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT c.id,c.type,c.title,c.created_at,other.user_id AS other_id,u.username,p.display_name,p.avatar_url," +
      "(SELECT m.content FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message," +
      "(SELECT m.created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message_at," +
      "(SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id AND m.sender_id<>? AND m.created_at>COALESCE(mine.last_read_at,'1970-01-01T00:00:00.000Z')) AS unread_count " +
      "FROM conversations c JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? " +
      "JOIN conversation_members other ON other.conversation_id=c.id AND other.user_id<>? " +
      "LEFT JOIN users u ON u.id=other.user_id LEFT JOIN profiles p ON p.user_id=other.user_id " +
      "WHERE c.type='direct' ORDER BY COALESCE(last_message_at,c.created_at) DESC LIMIT 100"
    ).bind(auth.sub, auth.sub, auth.sub).all();
    return json({ items: (rows.results || []).map(row => ({
      id: row.id, type: row.type, title: row.title,
      createdAt: row.created_at, lastMessage: row.last_message || "",
      lastMessageAt: row.last_message_at || row.created_at,
      unreadCount: Number(row.unread_count || 0),
      participant: { id: row.other_id, username: row.username, displayName: row.display_name || row.username, avatarUrl: row.avatar_url }
    })) });
  }

  if (path === "/v1/conversations" && method === "POST") {
    const input = await readJson(request);
    if (!input || !text(input.username, 24) || !/^[a-zA-Z0-9_]{3,24}$/.test(input.username.trim())) {
      return json({ error: "validation_error", message: "Username penerima tidak sah." }, 400);
    }
    const recipient = await env.DB.prepare(
      "SELECT id,username FROM users WHERE username=? COLLATE NOCASE AND status='active'"
    ).bind(input.username.trim()).first();
    if (!recipient) return json({ error: "user_not_found", message: "Pengguna tidak ditemui." }, 404);
    if (recipient.id === auth.sub) return json({ error: "cannot_message_self", message: "Anda tidak boleh memulakan perbualan dengan akaun sendiri." }, 400);
    let existing = await env.DB.prepare(
      "SELECT c.id FROM conversations c " +
      "JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? " +
      "JOIN conversation_members other ON other.conversation_id=c.id AND other.user_id=? " +
      "WHERE c.type='direct' AND (SELECT COUNT(*) FROM conversation_members all_members WHERE all_members.conversation_id=c.id)=2 LIMIT 1"
    ).bind(auth.sub, recipient.id).first();
    if (existing) return json({ conversation: { id: existing.id }, created: false });
    const id = uuid(), now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO conversations (id,type,title,created_by,created_at) VALUES (?,'direct',NULL,?,?)").bind(id, auth.sub, now),
      env.DB.prepare("INSERT INTO conversation_members (conversation_id,user_id,joined_at,last_read_at) VALUES (?,?,?,?)").bind(id, auth.sub, now, now),
      env.DB.prepare("INSERT INTO conversation_members (conversation_id,user_id,joined_at,last_read_at) VALUES (?,?,?,NULL)").bind(id, recipient.id, now)
    ]);
    return json({ conversation: { id }, created: true }, 201);
  }

  const conversationMessagesMatch = path.match(/^\/v1\/conversations\/([0-9a-f-]+)\/messages$/i);
  if (conversationMessagesMatch) {
    const conversationId = conversationMessagesMatch[1];
    const membership = await env.DB.prepare(
      "SELECT conversation_id FROM conversation_members WHERE conversation_id=? AND user_id=?"
    ).bind(conversationId, auth.sub).first();
    if (!membership) return json({ error: "conversation_not_found" }, 404);
    if (method === "GET") {
      const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") || 50)));
      const rows = await env.DB.prepare(
        "SELECT m.id,m.conversation_id,m.sender_id,m.content,m.media_id,m.status,m.created_at,m.edited_at,u.username,p.display_name,p.avatar_url " +
        "FROM messages m JOIN users u ON u.id=m.sender_id LEFT JOIN profiles p ON p.user_id=m.sender_id " +
        "WHERE m.conversation_id=? ORDER BY m.created_at DESC LIMIT ?"
      ).bind(conversationId, limit).all();
      const now = new Date().toISOString();
      await env.DB.prepare("UPDATE conversation_members SET last_read_at=? WHERE conversation_id=? AND user_id=?").bind(now, conversationId, auth.sub).run();
      return json({ items: (rows.results || []).reverse().map(row => ({
        id: row.id, conversationId: row.conversation_id, senderId: row.sender_id,
        content: row.content, mediaId: row.media_id, status: row.status,
        createdAt: row.created_at, editedAt: row.edited_at,
        sender: { username: row.username, displayName: row.display_name || row.username, avatarUrl: row.avatar_url }
      })) });
    }
    if (method === "POST") {
      const input = await readJson(request);
      if (!input || !text(input.content, 4000)) return json({ error: "validation_error", message: "Mesej diperlukan (maksimum 4,000 aksara)." }, 400);
      const id = uuid(), now = new Date().toISOString();
      await env.DB.prepare(
        "INSERT INTO messages (id,conversation_id,sender_id,content,media_id,status,created_at,edited_at) VALUES (?,?,?,?,NULL,'sent',?,NULL)"
      ).bind(id, conversationId, auth.sub, input.content.trim(), now).run();
      return json({ message: { id, conversationId, senderId: auth.sub, content: input.content.trim(), mediaId: null, status: "sent", createdAt: now } }, 201);
    }
  }

  return json({ error: "not_found" }, 404);
}

export default {
  async fetch(request, env) {
    const headers = corsHeaders(request, env);
    if (request.method === "OPTIONS") {
      if (!Object.keys(headers).length) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers });
    }
    try {
      const response = await route(request, env);
      const resultHeaders = new Headers(response.headers);
      for (const [key, value] of Object.entries(headers)) resultHeaders.set(key, value);
      resultHeaders.set("x-content-type-options", "nosniff");
      resultHeaders.set("referrer-policy", "no-referrer");
      resultHeaders.set("x-frame-options", "DENY");
      resultHeaders.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers: resultHeaders });
    } catch (error) {
      console.error("GomoGie API error", error);
      return json({ error: "internal_error", message: "Ralat pelayan. Cuba lagi." }, 500, {
        ...headers,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "x-frame-options": "DENY"
      });
    }
  }
};
