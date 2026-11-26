import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";

const apiUrl = "https://gomogie-api.terajuciptabina.workers.dev/v1/push/public-key";
const subject = "mailto:terajuciptabina@gmail.com";

if (!process.env.CLOUDFLARE_API_TOKEN || !process.env.CLOUDFLARE_ACCOUNT_ID) {
  console.error("Cloudflare deployment credentials are missing.");
  process.exit(1);
}

// Keep the same VAPID identity across deployments so existing browser
// subscriptions remain valid. Only create a key pair when Push is unconfigured.
const response = await fetch(apiUrl, {
  headers: { accept: "application/json" },
  signal: AbortSignal.timeout(10000)
});
if (!response.ok) {
  throw new Error("Cannot verify the live Push configuration (HTTP " + response.status + "). Refusing to rotate VAPID keys.");
}
const current = await response.json();
if (current?.configured === true && typeof current.publicKey === "string" && current.publicKey.length > 40) {
  console.log("VAPID is already configured. Existing keys are preserved.");
  process.exit(0);
}
if (current?.configured !== false) {
  throw new Error("The live Push configuration response is invalid. Refusing to rotate VAPID keys.");
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
const privateJwk = JSON.stringify({
  kty: privateKey.kty,
  crv: privateKey.crv,
  x: privateKey.x,
  y: privateKey.y,
  d: privateKey.d
});

function putSecret(name, value) {
  const result = spawnSync("wrangler", ["secret", "put", name], {
    input: value + "\n",
    encoding: "utf8",
    env: process.env,
    stdio: ["pipe", "inherit", "inherit"]
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error("Wrangler failed while configuring " + name);
}

putSecret("VAPID_PUBLIC_KEY", publicKeyBytes);
putSecret("VAPID_PRIVATE_JWK", privateJwk);
putSecret("VAPID_SUBJECT", subject);
console.log("A new VAPID key pair has been generated and stored as Cloudflare Worker secrets.");
console.log("The private key was not printed or written to the repository.");
