import { createLegacyMcpHandler } from "agents/mcp";
import { createServer } from "./server.js";

type LegacyHandler = ReturnType<typeof createLegacyMcpHandler>;
type WorkerContext = Parameters<LegacyHandler>[2];

type Env = {
  MCP_AUTH_TOKEN: string;
  DOKPLOY_URL: string;
  DOKPLOY_API_KEY: string;
  DOKPLOY_CUSTOM_HEADERS?: string;
  DOKPLOY_ENABLED_TAGS?: string;
  DOKPLOY_DISABLED_TAGS?: string;
  DOKPLOY_TOOL_PRESET?: string;
  DOKPLOY_TIMEOUT?: string;
  DOKPLOY_RETRY_ATTEMPTS?: string;
  DOKPLOY_RETRY_DELAY?: string;
  DOKPLOY_REDACT_ENV?: string;
  DOKPLOY_REDACT_FIELDS?: string;
};

const encoder = new TextEncoder();

async function tokenMatches(provided: string, expected: string): Promise<boolean> {
  const a = encoder.encode(provided);
  const b = encoder.encode(expected);
  if (a.byteLength !== b.byteLength) return false;
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", a),
    crypto.subtle.digest("SHA-256", b),
  ]);
  const av = new Uint8Array(ha);
  const bv = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < av.length; i++) diff |= av[i]! ^ bv[i]!;
  return diff === 0;
}

async function isAuthorized(request: Request, env: Env): Promise<boolean> {
  if (!env.MCP_AUTH_TOKEN) return false;
  const authorization = request.headers.get("authorization");
  if (!authorization) return false;
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return false;
  return tokenMatches(match[1]!, env.MCP_AUTH_TOKEN);
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });

export default {
  async fetch(request: Request, env: Env, ctx: WorkerContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return json({ status: "ok", runtime: "cloudflare-workers" });
    }

    if (url.pathname !== "/mcp") {
      return json({ error: "not_found" }, 404);
    }

    if (!(await isAuthorized(request, env))) {
      const response = json({ error: "unauthorized" }, 401);
      response.headers.set("www-authenticate", 'Bearer realm="dokploy-mcp"');
      return response;
    }

    const missing = [
      !env.DOKPLOY_URL && "DOKPLOY_URL",
      !env.DOKPLOY_API_KEY && "DOKPLOY_API_KEY",
    ].filter(Boolean);
    if (missing.length > 0) {
      return json({ error: "misconfigured", missing }, 503);
    }

    return createLegacyMcpHandler(createServer())(request, env, ctx);
  },
};
