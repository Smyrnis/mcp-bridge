import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

process.env.MCP_BRIDGE_TEST_MODE = "1";

const { fetchWithNodeHttp, isSameOrigin, sanitizeRedirectHeaders } = await import("../index.js");

function listen(server) {
  return new Promise((resolveListen) => {
    server.listen(0, "127.0.0.1", () => resolveListen(server.address().port));
  });
}

async function withServer(handler, run) {
  const server = createServer(handler);
  const port = await listen(server);
  try {
    await run(`http://127.0.0.1:${port}`, port);
  } finally {
    await new Promise((resolveClose) => server.close(resolveClose));
  }
}

test("isSameOrigin compares protocol, hostname, and port", () => {
  const base = new URL("https://mcp.example.test:8443/a");

  assert.equal(isSameOrigin(base, new URL("https://mcp.example.test:8443/b")), true);
  assert.equal(isSameOrigin(base, new URL("http://mcp.example.test:8443/b")), false);
  assert.equal(isSameOrigin(base, new URL("https://other.example.test:8443/b")), false);
  assert.equal(isSameOrigin(base, new URL("https://mcp.example.test:9443/b")), false);
});

test("sanitizeRedirectHeaders leaves headers untouched on a same-origin redirect", () => {
  const fromUrl = new URL("https://mcp.example.test/a");
  const toUrl = new URL("https://mcp.example.test/b");
  const headers = {
    authorization: "Bearer secret-token",
    cookie: "session=abc",
    "proxy-authorization": "Basic proxy-secret",
    "x-api-key": "api-secret",
    accept: "application/json"
  };

  const sanitized = sanitizeRedirectHeaders(headers, fromUrl, toUrl);

  assert.deepEqual(sanitized, headers);
});

test("sanitizeRedirectHeaders strips authorization, cookie, proxy-authorization, and x-api-key on a cross-origin redirect", () => {
  const fromUrl = new URL("https://mcp.example.test/a");
  const toUrl = new URL("https://attacker.example.test/b");
  const headers = {
    authorization: "Bearer secret-token",
    cookie: "session=abc",
    "proxy-authorization": "Basic proxy-secret",
    "x-api-key": "api-secret",
    accept: "application/json",
    "content-type": "application/json"
  };

  const sanitized = sanitizeRedirectHeaders(headers, fromUrl, toUrl);

  assert.equal(sanitized.authorization, undefined);
  assert.equal(sanitized.cookie, undefined);
  assert.equal(sanitized["proxy-authorization"], undefined);
  assert.equal(sanitized["x-api-key"], undefined);
  assert.equal(sanitized.accept, "application/json");
  assert.equal(sanitized["content-type"], "application/json");
});

test("sanitizeRedirectHeaders strips a cross-origin redirect that only changes port", () => {
  const fromUrl = new URL("https://mcp.example.test:443/a");
  const toUrl = new URL("https://mcp.example.test:8443/b");
  const headers = { "x-api-key": "api-secret" };

  const sanitized = sanitizeRedirectHeaders(headers, fromUrl, toUrl);

  assert.equal(sanitized["x-api-key"], undefined);
});

test("fetchWithNodeHttp strips the API key and bearer token when a redirect crosses origins", async () => {
  const capturedRequests = [];
  const targetHandler = (request, response) => {
    capturedRequests.push({ headers: request.headers, url: request.url });
    response.end("ok");
  };

  await withServer(targetHandler, async (targetOrigin) => {
    const redirectHandler = (request, response) => {
      capturedRequests.push({ headers: request.headers, url: request.url });
      response.writeHead(302, { location: `${targetOrigin}/next` });
      response.end();
    };

    await withServer(redirectHandler, async (redirectOrigin) => {
      const response = await fetchWithNodeHttp(`${redirectOrigin}/start`, {
        headers: {
          authorization: "Bearer secret-token",
          "x-api-key": "api-secret",
          accept: "text/plain"
        }
      }, { ca: undefined, redirectCount: 0 });

      assert.equal(response.status, 200);
      assert.equal(capturedRequests.length, 2);

      const [initialRequest, redirectedRequest] = capturedRequests;
      assert.equal(initialRequest.headers.authorization, "Bearer secret-token");
      assert.equal(initialRequest.headers["x-api-key"], "api-secret");

      assert.equal(redirectedRequest.headers.authorization, undefined);
      assert.equal(redirectedRequest.headers["x-api-key"], undefined);
      assert.equal(redirectedRequest.headers.accept, "text/plain");
    });
  });
});

test("fetchWithNodeHttp preserves the API key and bearer token when a redirect stays on the same origin", async () => {
  const capturedRequests = [];
  const handler = (request, response) => {
    capturedRequests.push({ headers: request.headers, url: request.url });
    if (request.url === "/start") {
      response.writeHead(302, { location: "/next" });
      response.end();
      return;
    }
    response.end("ok");
  };

  await withServer(handler, async (origin) => {
    const response = await fetchWithNodeHttp(`${origin}/start`, {
      headers: {
        authorization: "Bearer secret-token",
        "x-api-key": "api-secret"
      }
    }, { ca: undefined, redirectCount: 0 });

    assert.equal(response.status, 200);
    assert.equal(capturedRequests.length, 2);

    const [, redirectedRequest] = capturedRequests;
    assert.equal(redirectedRequest.headers.authorization, "Bearer secret-token");
    assert.equal(redirectedRequest.headers["x-api-key"], "api-secret");
  });
});
