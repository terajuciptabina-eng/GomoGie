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
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 310000 }, key, 256);
  return "pbkdf2-sha256$310000$" + b64url(salt) + "$" + b64url(new Uint8Array(bits));
}

async function passwordVerify(password, stored) {
  try {
    const [scheme, rounds, saltText, hashText] = stored.split("$");
    if (scheme !== "pbkdf2-sha256" || Number(rounds) !== 310000) return false;
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64url(saltText), iterations: 310000 }, key, 256);
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
        typeof input.password !== "string" || input.password.length < 12 || input.password.length > 128 ||
        !text(input.displayName, 60)) {
      return json({ error: "validation_error", message: "Email, username, kata laluan (12–128 aksara) dan nama paparan diperlukan." }, 400);
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
  const needsAuth = path === "/v1/auth/me" || (path.startsWith("/v1/posts") && !publicCommentsRead) || path.startsWith("/v1/users/") || path.startsWith("/v1/notifications");
  const auth = needsAuth ? await authenticate(request, env) : null;
  if (needsAuth && !auth) return json({ error: "unauthorized", message: "Sila log masuk semula." }, 401);

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
      "SELECT p.id,p.user_id,p.content,p.visibility,p.created_at,p.comments_enabled, u.username, pr.display_name,pr.avatar_url, (SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) AS reaction_count, (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id AND c.status='published') AS comment_count FROM posts p JOIN users u ON u.id=p.user_id LEFT JOIN profiles pr ON pr.user_id=p.user_id WHERE p.status='published' AND p.visibility='public' ORDER BY p.created_at DESC LIMIT ?"
    ).bind(limit).all();
    return json({ items: (rows.results || []).map(row => ({ id: row.id, content: row.content, visibility: row.visibility, createdAt: row.created_at, commentsEnabled: Boolean(row.comments_enabled), author: { id: row.user_id, username: row.username, displayName: row.display_name, avatarUrl: row.avatar_url }, reactionCount: row.reaction_count, commentCount: row.comment_count })) });
  }

  if (path === "/v1/posts" && method === "POST") {
    const input = await readJson(request);
    if (!input || !text(input.content, 5000)) return json({ error: "validation_error", message: "Kandungan posting diperlukan (maksimum 5,000 aksara)." }, 400);
    const visibility = ["public", "followers", "private"].includes(input.visibility) ? input.visibility : "public";
    const id = uuid(), now = new Date().toISOString();
    await env.DB.prepare("INSERT INTO posts (id,user_id,content,visibility,status,comments_enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
      .bind(id, auth.sub, input.content.trim(), visibility, "published", input.commentsEnabled === false ? 0 : 1, now, now).run();
    return json({ post: { id, userId: auth.sub, content: input.content.trim(), visibility, status: "published", createdAt: now } }, 201);
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
