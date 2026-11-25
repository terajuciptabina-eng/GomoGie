const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
});

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

export default {
  async fetch(request, env) {
    const headers = corsHeaders(request, env);
    if (request.method === "OPTIONS") {
      if (!Object.keys(headers).length) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers });
    }

    const url = new URL(request.url);
    if (url.pathname === "/health/live" && request.method === "GET") {
      return json({ status: "ok", service: "gomogie-api", runtime: "cloudflare-workers" }, 200, headers);
    }

    if (url.pathname === "/health/ready" && request.method === "GET") {
      try {
        await env.DB.prepare("SELECT 1 AS ready").first();
        return json({ status: "ready", database: "connected" }, 200, headers);
      } catch {
        return json({ status: "not_ready", database: "unavailable" }, 503, headers);
      }
    }

    if (url.pathname === "/" && request.method === "GET") {
      return json({ service: "gomogie-api", status: "staging-foundation" }, 200, headers);
    }

    return json({ error: "not_found" }, 404, headers);
  }
};
