# GomoGie Media Upload — Implementation & Operations Guide

**Scope:** Persistent image upload for profile photos, profile cover photos and image posts.  
**Storage:** Cloudflare R2 for binary files; Cloudflare D1 for ownership and metadata; Cloudflare Worker for authenticated upload and delivery.  
**Frontend:** GitHub Pages (index.html).  
**Last updated:** 25 November 2026.

## 1. Architecture

1. The browser sends a selected image as multipart/form-data to POST /v1/media.
2. The Worker requires the existing GomoGie Bearer access token and validates purpose, file size, declared MIME type and image file signature.
3. The Worker writes the image to the R2 binding MEDIA_BUCKET, using a server-generated object key. Client filenames are never used as object keys.
4. The Worker inserts owner, purpose, object key, MIME type, size and status into gomogie_media_assets.
5. For avatar and cover, the Worker updates the matching profile URL immediately. For post, the returned media ID is attached to a post by POST /v1/posts.
6. Public feed responses include the image URL. GET /v1/media/:mediaId streams the object from R2 with a fixed content type and immutable cache headers.

The browser's object URL is used only for a temporary local preview. It is not stored as the permanent media URL.

## 2. Supported behavior

| Surface | Behavior |
| --- | --- |
| Profile photo | Uploads and persists to profiles.avatar_url |
| Profile cover | Uploads and persists to profiles.cover_url |
| Image post | Uploads first, then attaches the owned media ID to the created post |
| Feed | Returns and renders attached image posts |
| Profile page | Uses the saved profile photo and cover on reload and other devices |

Supported image formats: JPEG, PNG, WebP and GIF. Maximum image size: 8 MiB (8,388,608 bytes). SVG is intentionally not accepted.

Video upload/transcoding and multiple images per post are not part of this implementation.

## 3. D1 schema

The migration is additive and does not alter existing tables:

- workers/api/sql/0002_media_storage.sql

It creates:

- gomogie_media_assets: media ownership, purpose, R2 object key, verified MIME type, byte size and status.
- gomogie_post_media: relation between a post and its uploaded image.

Existing media_assets and post_media tables are left untouched because their exact legacy columns are not required by this feature. Do not apply the PostgreSQL migrations under backend/migrations to this D1 database.

## 4. One-time Cloudflare prerequisites

The Worker configuration contains the R2 binding:

~~~toml
[[r2_buckets]]
binding = "MEDIA_BUCKET"
bucket_name = "gomogie-media"
~~~

The Cloudflare account must contain an R2 bucket named gomogie-media. If a bucket with that name already exists, reuse it; do not create a duplicate. If it does not exist, create it once in Cloudflare R2 (or with npx wrangler r2 bucket create gomogie-media).

The existing D1 binding DB, Worker name, API hostname and JWT_SECRET are retained. Do not recreate the database or replace the secret.

## 5. Apply the D1 migration

From the workers/api directory, after Wrangler is authenticated to the same Cloudflare account:

~~~sh
npx wrangler d1 execute gomogie-db --remote --file=sql/0002_media_storage.sql
~~~

The migration uses CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS; it is safe to rerun. Confirm the command reports success before deploying the Worker.

## 6. Deploy the Worker

From workers/api:

~~~sh
npx wrangler deploy
~~~

The existing JWT_SECRET Worker secret is not changed by this deployment. The configured R2 binding is included in the Wrangler deployment.

After deployment, check:

- GET https://gomogie-api.terajucibina.workers.dev/health/live
- GET https://gomogie-api.terajucibina.workers.dev/health/ready

These health checks confirm Worker liveness and D1 connectivity. They do not by themselves prove R2 upload functionality.

## 7. API contract

### Upload image

POST /v1/media — authenticated multipart request.

Fields:
- file: image file.
- purpose: avatar, cover or post.

Response (201):

~~~json
{
  "media": {
    "id": "media-uuid",
    "purpose": "post",
    "url": "https://gomogie-api.terajucibina.workers.dev/v1/media/media-uuid",
    "mimeType": "image/jpeg",
    "size": 123456,
    "createdAt": "ISO-8601 timestamp"
  }
}
~~~

For avatar and cover, the Worker persists the returned URL to the signed-in user's profile as part of the upload request.

### Deliver image

GET /v1/media/:mediaId — public read route for media marked ready. The response streams the R2 object and uses the MIME type recorded at upload time.

### Create image post

POST /v1/posts — authenticated JSON request. Upload with purpose post first, then pass the returned media.id:

~~~json
{
  "content": "A caption for the photo",
  "visibility": "public",
  "mediaId": "media-uuid"
}
~~~

The Worker verifies that the media belongs to the authenticated user and was uploaded for the post purpose before attaching it.

## 8. Validation and security

- Upload requires a valid existing GomoGie access token.
- Upload size is capped at 8 MiB; request content-length is bounded before parsing.
- Only JPEG, PNG, WebP and GIF are accepted.
- File signatures are checked; MIME header alone is not trusted.
- SVG and arbitrary files are rejected.
- Object keys and media IDs are generated server-side.
- Post media ownership is checked before attachment.
- R2 objects are delivered with the database-verified MIME type and X-Content-Type-Options: nosniff.
- Public post images are intentionally readable by anyone who can view the public feed. Do not upload confidential images.
- This feature does not include image moderation, virus scanning, image resizing, EXIF stripping, quota enforcement or automated orphan cleanup. These remain hardening tasks before large-scale public use.

## 9. Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| media_storage_unavailable | R2 binding missing from deployed Worker | Confirm MEDIA_BUCKET points to gomogie-media, then redeploy |
| no such table: gomogie_media_assets | D1 migration not applied to remote database | Apply section 5 migration to the existing gomogie-db |
| unsupported_image | Unsupported format or file signature mismatch | Use JPEG, PNG, WebP or GIF |
| file_size_invalid | Image exceeds 8 MiB | Compress or resize image |
| unauthorized | Session expired or missing | Log in again |
| media_not_found | Invalid media ID or missing R2 object | Verify the D1 row and matching R2 object |

## 10. Manual acceptance test

1. Log in on desktop and upload a profile photo.
2. Reload the page; confirm the photo remains.
3. Upload a cover photo and reload; confirm it remains.
4. Log in on a second browser/device; confirm both profile images are visible.
5. Publish a post with an image and caption.
6. Reload the feed; confirm the image and caption remain.
7. Open the post on a mobile browser; confirm the image scales to the viewport.
8. Try an unsupported file and a file larger than 8 MiB; confirm the UI/API rejects them without publishing.
9. Confirm a different signed-in user cannot attach another user's media ID to their post.

## 11. Current completion boundary

The source code and schema migration implement the image upload path. Production readiness still depends on applying the D1 migration, ensuring the R2 bucket exists, deploying the updated Worker, and running the acceptance tests above. Do not mark uploads as live-tested until those steps have actually succeeded.
