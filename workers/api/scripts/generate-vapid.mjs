import { generateKeyPairSync } from "node:crypto";

const suppliedSubject = process.argv[2] || process.env.VAPID_SUBJECT || "mailto:terajuciptabina@gmail.com";
const contactEmail = suppliedSubject.replace(/^mailto:/i, "").trim().toLowerCase();
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
  console.error("Usage: node scripts/generate-vapid.mjs <monitored-email>");
  console.error("Provide an email address that GomoGie users can use to contact the operator.");
  process.exit(1);
}

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
console.log("VAPID_SUBJECT=mailto:" + contactEmail);
