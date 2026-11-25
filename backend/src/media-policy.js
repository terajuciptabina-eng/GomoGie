export const MEDIA_TYPES = Object.freeze({ image: Object.freeze(['image/jpeg','image/png','image/webp','image/avif']), video: Object.freeze(['video/mp4','video/webm','video/quicktime']) });
export function getMediaPolicy(mediaType, contentType, env = process.env) {
  const accepted = MEDIA_TYPES[mediaType];
  if (!accepted) throw new TypeError('Unsupported media category');
  if (!accepted.includes(contentType)) throw new TypeError('Unsupported media content type');
  const fallback = mediaType === 'image' ? 10 * 1024 * 1024 : 100 * 1024 * 1024;
  const configured = Number(mediaType === 'image' ? env.R2_MAX_IMAGE_BYTES || fallback : env.R2_MAX_VIDEO_BYTES || fallback);
  if (!Number.isSafeInteger(configured) || configured < 1) throw new TypeError('Invalid media size configuration');
  return { mediaType, contentType, maxBytes: configured };
}
