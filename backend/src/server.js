import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { getMediaPolicy } from './media-policy.js';
import { S3Client, PutObjectCommand, HeadObjectCommand, CopyObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const { Pool } = pg;
const env = process.env;
const required = ['DATABASE_URL', 'JWT_SECRET'];
for (const key of required) {
  if (!env[key]) throw new Error(`Missing required environment variable: ${key}`);
}
if (env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters');

const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: Number(env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ...(env.DATABASE_SSL === 'true' ? { ssl: { rejectUnauthorized: true } } : {})
});

const app = Fastify({
  logger: true,
  bodyLimit: Number(env.MAX_JSON_BODY_BYTES || 1048576),
  trustProxy: env.TRUST_PROXY === 'true'
});

const allowedOrigins = (env.CORS_ORIGINS || '').split(',').map(v => v.trim()).filter(Boolean);
await app.register(helmet, { global: true });
await app.register(cors, {
  credentials: true,
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed'), false);
  }
});
await app.register(jwt, { secret: env.JWT_SECRET, sign: { expiresIn: env.JWT_TTL || '15m' } });
await app.register(rateLimit, { max: 120, timeWindow: '1 minute' });

const uploadEnabled = Boolean(env.R2_ACCOUNT_ID && env.R2_ACCESS_KEY_ID && env.R2_SECRET_ACCESS_KEY && env.R2_BUCKET);
const s3 = uploadEnabled ? new S3Client({
  region: 'auto',
  endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY }
}) : null;

const emailSchema = z.string().trim().email().max(254).transform(v => v.toLowerCase());
const handleSchema = z.string().trim().toLowerCase().regex(/^[a-z0-9_]{3,24}$/);
const passwordSchema = z.string().min(12).max(72);
const publicProfile = (row) => ({
  id: row.id, handle: row.handle, displayName: row.display_name,
  bio: row.bio, createdAt: row.created_at
});

async function authenticate(request, reply) {
  try { await request.jwtVerify(); }
  catch { return reply.code(401).send({ error: 'unauthorized', message: 'Sesi tidak sah atau telah tamat.' }); }
}

app.setErrorHandler((error, request, reply) => {
  request.log.error({ err: error }, 'request failed');
  if (error?.code === '23505') return reply.code(409).send({ error: 'conflict', message: 'Email atau handle telah digunakan.' });
  if (error?.code === '23503') return reply.code(400).send({ error: 'invalid_reference', message: 'Rujukan data tidak sah.' });
  if (error?.name === 'ZodError') return reply.code(400).send({ error: 'validation_error', message: 'Input tidak sah.' });
  const status = Number(error.statusCode);
  if (status >= 400 && status < 500) return reply.code(status).send({ error: 'request_error', message: error.message });
  return reply.code(500).send({ error: 'internal_error', message: 'Ralat pelayan. Cuba lagi.' });
});

app.get('/health/live', async () => ({ status: 'ok', service: 'gomogie-api' }));
app.get('/health/ready', async (request, reply) => {
  await pool.query('SELECT 1');
  return { status: 'ready', database: 'connected' };
});

app.post('/v1/auth/register', {
  config: { rateLimit: { max: 5, timeWindow: '15 minutes' } }
}, async (request, reply) => {
  const schema = z.object({
    email: emailSchema,
    password: passwordSchema,
    handle: handleSchema,
    displayName: z.string().trim().min(1).max(60)
  });
  const input = schema.parse(request.body);
  const passwordHash = await bcrypt.hash(input.password, 12);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const created = await client.query(
      'INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,created_at',
      [input.email, passwordHash]
    );
    const user = created.rows[0];
    const profile = await client.query(
      'INSERT INTO profiles(user_id,handle,display_name) VALUES($1,$2,$3) RETURNING handle,display_name,bio,created_at',
      [user.id, input.handle, input.displayName]
    );
    await client.query('COMMIT');
    const token = app.jwt.sign({ sub: user.id, email: user.email });
    return reply.code(201).send({
      user: { id: user.id, email: user.email, emailVerified: false },
      profile: publicProfile({ id: user.id, ...profile.rows[0] }),
      accessToken: token,
      tokenType: 'Bearer',
      expiresIn: env.JWT_TTL || '15m',
      notice: 'Akaun beta: pengesahan email dan pemulihan kata laluan perlu diaktifkan sebelum pendaftaran awam.'
    });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
});

app.post('/v1/auth/login', {
  config: { rateLimit: { max: 8, timeWindow: '15 minutes' } }
}, async (request, reply) => {
  const input = z.object({ email: emailSchema, password: z.string().min(1).max(72) }).parse(request.body);
  const result = await pool.query(
    `SELECT u.id,u.email,u.password_hash,u.status,p.handle,p.display_name,p.bio,p.created_at
     FROM users u JOIN profiles p ON p.user_id=u.id WHERE u.email=$1`,
    [input.email]
  );
  const user = result.rows[0];
  if (!user || user.status !== 'active' || !(await bcrypt.compare(input.password, user.password_hash))) {
    return reply.code(401).send({ error: 'invalid_credentials', message: 'Email atau kata laluan tidak tepat.' });
  }
  const token = app.jwt.sign({ sub: user.id, email: user.email });
  return {
    user: { id: user.id, email: user.email },
    profile: publicProfile(user),
    accessToken: token,
    tokenType: 'Bearer',
    expiresIn: env.JWT_TTL || '15m'
  };
});

app.get('/v1/auth/me', { preHandler: authenticate }, async (request, reply) => {
  const result = await pool.query(
    `SELECT u.id,u.email,u.email_verified_at,p.handle,p.display_name,p.bio,p.created_at
     FROM users u JOIN profiles p ON p.user_id=u.id WHERE u.id=$1 AND u.status='active'`,
    [request.user.sub]
  );
  if (!result.rowCount) return reply.code(404).send({ error: 'not_found' });
  const row = result.rows[0];
  return {
    user: { id: row.id, email: row.email, emailVerified: Boolean(row.email_verified_at) },
    profile: publicProfile(row)
  };
});

app.get('/v1/feed', async (request, reply) => {
  const parsedLimit = z.coerce.number().int().min(1).max(50).default(20).safeParse(request.query.limit);
  if (!parsedLimit.success) return reply.code(400).send({ error: 'invalid_limit' });
  const limit = parsedLimit.data;
  let cursor = null;
  if (request.query.before) {
    try {
      const decoded = Buffer.from(request.query.before, 'base64url').toString('utf8');
      const [createdAt, id] = decoded.split('|');
      if (!createdAt || !z.string().uuid().safeParse(id).success || Number.isNaN(Date.parse(createdAt))) throw new Error('invalid cursor');
      cursor = { createdAt: new Date(createdAt).toISOString(), id };
    } catch { return reply.code(400).send({ error: 'invalid_cursor' }); }
  }
  const result = await pool.query(
    `SELECT p.id,p.body,p.created_at,p.author_id,pr.handle,pr.display_name,
       (SELECT count(*)::int FROM reactions r WHERE r.post_id=p.id) AS reaction_count,
       (SELECT count(*)::int FROM comments c WHERE c.post_id=p.id AND c.status='published') AS comment_count
     FROM posts p JOIN profiles pr ON pr.user_id=p.author_id
     WHERE p.status='published' AND p.visibility='public'
       AND ($1::timestamptz IS NULL OR (p.created_at,p.id) < ($1::timestamptz,$2::uuid))
     ORDER BY p.created_at DESC,p.id DESC LIMIT $3`,
    [cursor?.createdAt || null, cursor?.id || null, limit]
  );
  return { items: result.rows.map(row => ({
    id: row.id, body: row.body, createdAt: row.created_at,
    author: { id: row.author_id, handle: row.handle, displayName: row.display_name },
    reactionCount: row.reaction_count, commentCount: row.comment_count
  })), nextCursor: result.rows.length ? Buffer.from(`${result.rows[result.rows.length - 1].created_at.toISOString()}|${result.rows[result.rows.length - 1].id}`).toString('base64url') : null };
});

app.post('/v1/posts', { preHandler: authenticate }, async (request, reply) => {
  const input = z.object({
    body: z.string().trim().min(1).max(5000),
    visibility: z.enum(['public']).default('public')
  }).parse(request.body);
  const result = await pool.query(
    'INSERT INTO posts(author_id,body,visibility) VALUES($1,$2,$3) RETURNING id,body,visibility,created_at',
    [request.user.sub, input.body, input.visibility]
  );
  return reply.code(201).send({ post: result.rows[0] });
});

app.post('/v1/posts/:postId/reactions', { preHandler: authenticate }, async (request, reply) => {
  const postId = z.string().uuid().parse(request.params.postId);
  const input = z.object({ type: z.enum(['like','love','care','haha','wow','sad','angry']).default('like') }).parse(request.body || {});
  const result = await pool.query(
    `INSERT INTO reactions(user_id,post_id,reaction_type)
     SELECT $1,p.id,$3 FROM posts p WHERE p.id=$2 AND p.status='published' AND p.visibility='public'
     ON CONFLICT(user_id,post_id) DO UPDATE SET reaction_type=EXCLUDED.reaction_type
     RETURNING post_id,reaction_type`,
    [request.user.sub, postId, input.type]
  );
  if (!result.rowCount) return reply.code(404).send({ error: 'post_not_found' });
  return { reaction: result.rows[0] };
});

app.delete('/v1/posts/:postId/reactions', { preHandler: authenticate }, async (request, reply) => {
  const postId = z.string().uuid().parse(request.params.postId);
  await pool.query('DELETE FROM reactions WHERE user_id=$1 AND post_id=$2', [request.user.sub, postId]);
  return reply.code(204).send();
});

app.post('/v1/posts/:postId/comments', { preHandler: authenticate }, async (request, reply) => {
  const postId = z.string().uuid().parse(request.params.postId);
  const input = z.object({ body: z.string().trim().min(1).max(2000) }).parse(request.body);
  const result = await pool.query(
    `INSERT INTO comments(post_id,author_id,body)
     SELECT id,$2,$3 FROM posts WHERE id=$1 AND status='published' AND visibility='public'
     RETURNING id,post_id,body,created_at`,
    [postId, request.user.sub, input.body]
  );
  if (!result.rowCount) return reply.code(404).send({ error: 'post_not_found' });
  return reply.code(201).send({ comment: result.rows[0] });
});

app.post('/v1/users/:handle/follow', { preHandler: authenticate }, async (request, reply) => {
  const handle = handleSchema.parse(request.params.handle);
  const result = await pool.query(
    `INSERT INTO follows(follower_id,followed_id)
     SELECT $1,p.user_id FROM profiles p JOIN users u ON u.id=p.user_id
     WHERE p.handle=$2 AND u.status='active' AND p.user_id<>$1
     ON CONFLICT DO NOTHING RETURNING followed_id`,
    [request.user.sub, handle]
  );
  if (!result.rowCount) {
    const exists = await pool.query('SELECT 1 FROM profiles WHERE handle=$1', [handle]);
    if (!exists.rowCount) return reply.code(404).send({ error: 'user_not_found' });
  }
  return { following: true };
});

app.delete('/v1/users/:handle/follow', { preHandler: authenticate }, async (request, reply) => {
  const handle = handleSchema.parse(request.params.handle);
  await pool.query(
    'DELETE FROM follows f USING profiles p WHERE f.followed_id=p.user_id AND f.follower_id=$1 AND p.handle=$2',
    [request.user.sub, handle]
  );
  return reply.code(204).send();
});

app.post('/v1/media/uploads', { preHandler: authenticate }, async (request, reply) => {
  if (!uploadEnabled) return reply.code(503).send({ error: 'media_storage_not_configured' });
  const input = z.object({
    mediaType: z.enum(['image','video']),
    contentType: z.string().min(1).max(100),
    sizeBytes: z.number().int().positive()
  }).parse(request.body);
  let policy;
  try { policy = getMediaPolicy(input.mediaType, input.contentType, env); }
  catch { return reply.code(415).send({ error: 'unsupported_media_type' }); }
  const maxBytes = policy.maxBytes;
  if (input.sizeBytes > maxBytes) return reply.code(413).send({ error: 'file_size_limit_exceeded', maxBytes });
  const reservedBytes = input.sizeBytes;
  const id = randomUUID();
  const extension = input.contentType.split('/')[1].replace('jpeg','jpg').replace('quicktime','mov');
  const objectKey = `uploads/${request.user.sub}/${id}.${extension}`;
  const expiresIn = Math.min(Math.max(Number(env.R2_UPLOAD_URL_TTL_SECONDS || 300), 60), 600);
  const expiresAt = new Date(Date.now() + expiresIn * 1000);
  const userCap = Number(env.R2_USER_STORAGE_CAP_BYTES || 524288000);
  const platformCap = Number(env.R2_PLATFORM_STORAGE_CAP_BYTES || 8589934592);
  if (!Number.isSafeInteger(userCap) || !Number.isSafeInteger(platformCap) || userCap < 1 || platformCap < 1 || reservedBytes > userCap || reservedBytes > platformCap) {
    return reply.code(413).send({ error: 'upload_limit_configuration_invalid' });
  }
  const quotaClient = await pool.connect();
  try {
    await quotaClient.query('BEGIN');
    await quotaClient.query('SELECT pg_advisory_xact_lock($1)', [812734612]);
    const usage = await quotaClient.query(
      `SELECT
        COALESCE((SELECT SUM(size_bytes) FROM media_assets WHERE owner_id=$1 AND status <> 'deleted'),0)
        + COALESCE((SELECT SUM(max_bytes) FROM media_upload_intents WHERE owner_id=$1 AND status='pending' AND expires_at > now()),0) AS user_bytes,
        COALESCE((SELECT SUM(size_bytes) FROM media_assets WHERE status <> 'deleted'),0)
        + COALESCE((SELECT SUM(max_bytes) FROM media_upload_intents WHERE status='pending' AND expires_at > now()),0) AS platform_bytes`,
      [request.user.sub]
    );
    const userBytes = Number(usage.rows[0].user_bytes);
    const platformBytes = Number(usage.rows[0].platform_bytes);
    if (userBytes + reservedBytes > userCap) {
      await quotaClient.query('ROLLBACK');
      return reply.code(413).send({ error: 'user_storage_quota_exceeded', message: 'Had storan akaun telah dicapai.' });
    }
    if (platformBytes + reservedBytes > platformCap) {
      await quotaClient.query('ROLLBACK');
      return reply.code(507).send({ error: 'platform_storage_quota_reached', message: 'Muat naik sementara dihentikan kerana had storan platform.' });
    }
    await quotaClient.query(
      'INSERT INTO media_upload_intents(owner_id,object_key,media_type,content_type,max_bytes,expires_at) VALUES($1,$2,$3,$4,$5,$6)',
      [request.user.sub, objectKey, input.mediaType, input.contentType, reservedBytes, expiresAt]
    );
    await quotaClient.query('COMMIT');
  } catch (error) {
    await quotaClient.query('ROLLBACK');
    throw error;
  } finally { quotaClient.release(); }
  const command = new PutObjectCommand({
    Bucket: env.R2_BUCKET, Key: objectKey, ContentType: input.contentType, ContentLength: reservedBytes,
    Metadata: { owner: request.user.sub, intent: id }
  });
  const uploadUrl = await getSignedUrl(s3, command, { expiresIn });
  return reply.code(201).send({
    uploadId: id, uploadUrl, method: 'PUT',
    headers: { 'Content-Type': input.contentType, 'x-amz-meta-owner': request.user.sub, 'x-amz-meta-intent': id },
    maxBytes, expectedBytes: reservedBytes, expiresAt
  });
});

app.post('/v1/media/uploads/:uploadId/complete', { preHandler: authenticate }, async (request, reply) => {
  if (!uploadEnabled) return reply.code(503).send({ error: 'media_storage_not_configured' });
  const uploadId = z.string().uuid().parse(request.params.uploadId);
  const intentResult = await pool.query(
    `SELECT * FROM media_upload_intents
     WHERE id=$1 AND owner_id=$2 AND status='pending' AND expires_at > now()`,
    [uploadId, request.user.sub]
  );
  if (!intentResult.rowCount) return reply.code(404).send({ error: 'upload_intent_not_found_or_expired' });
  const intent = intentResult.rows[0];
  const head = await s3.send(new HeadObjectCommand({ Bucket: env.R2_BUCKET, Key: intent.object_key }));
  if (!head.ContentLength || head.ContentLength !== Number(intent.max_bytes) || head.ContentType !== intent.content_type || head.Metadata?.owner !== request.user.sub || head.Metadata?.intent !== uploadId) {
    try { await s3.send(new DeleteObjectCommand({ Bucket: env.R2_BUCKET, Key: intent.object_key })); }
    catch (error) { request.log.warn({ err: error }, 'could not remove rejected staging object'); }
    await pool.query('UPDATE media_upload_intents SET status=$1 WHERE id=$2', ['rejected', uploadId]);
    return reply.code(400).send({ error: 'uploaded_file_failed_validation' });
  }
  const fileName = intent.object_key.split('/').pop();
  const quarantineKey = `quarantine/${request.user.sub}/${fileName}`;
  const copySource = `${env.R2_BUCKET}/${intent.object_key.split('/').map(encodeURIComponent).join('/')}`;
  await s3.send(new CopyObjectCommand({
    Bucket: env.R2_BUCKET, Key: quarantineKey, CopySource: copySource, MetadataDirective: 'COPY'
  }));
  await s3.send(new DeleteObjectCommand({ Bucket: env.R2_BUCKET, Key: intent.object_key }));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const asset = await client.query(
      `INSERT INTO media_assets(owner_id,object_key,media_type,content_type,size_bytes)
       VALUES($1,$2,$3,$4,$5) RETURNING id,media_type,content_type,size_bytes,created_at`,
      [request.user.sub, quarantineKey, intent.media_type, intent.content_type, head.ContentLength]
    );
    await client.query('UPDATE media_upload_intents SET status=$1 WHERE id=$2', ['completed', uploadId]);
    await client.query('COMMIT');
    return reply.code(201).send({
      media: { ...asset.rows[0], status: 'quarantined' },
      notice: 'Fail disahkan pada peringkat metadata. Imbasan malware dan transkod video masih perlu diaktifkan sebelum penerbitan awam.'
    });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
});

app.addHook('onClose', async () => { await pool.end(); });
const port = Number(env.PORT || 3000);
const host = env.HOST || '0.0.0.0';
await app.listen({ port, host });
