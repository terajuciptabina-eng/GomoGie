import { generateKeyPairSync } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
  publicKeyEncoding: { format: "jwk" },
  privateKeyEncoding: { format: "jwk" }
});
const publicKeyBytes = Buffer.concat([
  Buffer.from([4]),
  Buffer.from(publicKey.x, "base64url"),
  Buffer.from(publicKey.y, "base64url")
]).toString("base64url");

console.log("VAPID_PUBLIC_KEY=" + publicKeyBytes);
console.log("VAPID_PRIVATE_JWK=" + JSON.stringify({
  kty: privateKey.kty, crv: privateKey.crv,
  x: privateKey.x, y: privateKey.y, d: privateKey.d
}));
console.log("VAPID_SUBJECT=mailto:admin@gomogie.com");
