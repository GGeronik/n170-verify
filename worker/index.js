// Everything is denied unless listed: scripts, styles and images come only from
// this origin, inline scripts and styles are refused, Trusted Types blocks DOM
// injection sinks, and scripts can't open network connections.
const SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy": [
    "default-src 'none'",
    "base-uri 'none'",
    "connect-src 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "img-src 'self'",
    "object-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "worker-src 'none'",
    "require-trusted-types-for 'script'",
    "trusted-types 'none'",
    "upgrade-insecure-requests",
  ].join("; "),
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Origin-Agent-Cluster": "?1",
  "Permissions-Policy": "accelerometer=(), bluetooth=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-DNS-Prefetch-Control": "off",
  "X-Frame-Options": "DENY",
});

function acceptsHtml(request) {
  return (request.headers.get("accept") ?? "")
    .split(",")
    .some((value) => value.trim().split(";", 1)[0].toLowerCase() === "text/html");
}

// Our Markdown/plain-text assets are UTF-8. Keep other MIME types and parameters.
export function utf8DocumentationContentType(contentType, pathname = "") {
  if (!contentType) {
    if (/\.md$/i.test(pathname)) contentType = "text/markdown";
    else if (/\.txt$|\/(?:NOTICE|SHA256SUMS)$/i.test(pathname)) contentType = "text/plain";
  }
  if (!contentType) return contentType;
  const [mediaType, ...parameters] = contentType.split(/;(?=(?:[^"]*"[^"]*")*[^"]*$)/);
  if (!/^text\/(?:plain|markdown|x-markdown)$/i.test(mediaType.trim())) return contentType;
  return [mediaType, ...parameters.filter((parameter) => !/^\s*charset\s*=/i.test(parameter))].join(";") + "; charset=utf-8";
}

function withSecurityHeaders(response, pathname) {
  const headers = new Headers(response.headers);
  const contentType = utf8DocumentationContentType(headers.get("Content-Type"), pathname);
  if (contentType) headers.set("Content-Type", contentType);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    const response = await env.ASSETS.fetch(request);

    if (response.status !== 404 || !acceptsHtml(request) || !["GET", "HEAD"].includes(request.method)) {
      return withSecurityHeaders(response, new URL(request.url).pathname);
    }

    const indexUrl = new URL(request.url);
    indexUrl.pathname = "/index.html";
    indexUrl.search = "";
    return withSecurityHeaders(await env.ASSETS.fetch(new Request(indexUrl, request)), indexUrl.pathname);
  },
};
