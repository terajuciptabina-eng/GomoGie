import test from 'node:test';
import assert from 'node:assert/strict';
import { getMediaPolicy } from '../src/media-policy.js';

test('accepts supported image formats and applies the image size default', () => {
  assert.equal(getMediaPolicy('image', 'image/webp', {}).maxBytes, 10 * 1024 * 1024);
});
test('accepts supported video formats and applies the video size default', () => {
  assert.equal(getMediaPolicy('video', 'video/mp4', {}).maxBytes, 100 * 1024 * 1024);
});
test('rejects unsupported media formats', () => {
  assert.throws(() => getMediaPolicy('image', 'image/svg+xml', {}), /Unsupported/);
});
test('rejects invalid configured upload limits', () => {
  assert.throws(() => getMediaPolicy('video', 'video/mp4', { R2_MAX_VIDEO_BYTES: '-1' }), /Invalid/);
});
test('honours explicit platform upload limits', () => {
  assert.equal(getMediaPolicy('image', 'image/jpeg', { R2_MAX_IMAGE_BYTES: '5242880' }).maxBytes, 5242880);
});
