# Frontend, DOM & Browser Security

**Scope:** DOM XSS, Sanitizer API, DOM Clobbering, `postMessage`, Service Workers, Clickjacking, CSP, Frontend JS CVEs.
**Related WSS Rules:** `NEXT-003`, `JS-CVE-001`, `HAR-HDR-001`, `HAR-HDR-004`, `IPC-001`.

## 1. Zero-Trust DOM Sinks
- **Prefer safe text APIs:** Always use `element.textContent` or `document.createTextNode()` for untrusted strings.
- **Sanitized HTML only:** When rich HTML rendering is strictly required, use the native Sanitizer API (`element.setHTML()`), `window.vibeSetHTML(el, html)`, or pinned/updated `DOMPurify.sanitize(html)` with safe URI schemes (`https:`, `http:`, `mailto:`).
- **Forbidden sinks:** Never use `eval()`, `new Function()`, `document.write()`, or unescaped `innerHTML` / `outerHTML` / `dangerouslySetInnerHTML` with user, API, or LLM-generated strings.

## 2. `window.postMessage` & Cross-Document Messaging (`NEXT-003`)
- **Sender side:** Never pass `"*"` as `targetOrigin` when sending tokens, PII, or state; specify the exact origin (`https://app.example.com`).
- **Receiver side:** Always validate `event.origin === EXPECTED_ORIGIN` as the very first line inside `window.addEventListener("message", ...)` and validate the message schema before acting on it.

## 3. DOM Clobbering, Service Workers & CSPT
- **Prevent DOM Clobbering:** Do not read configuration or security flags from global `window.*` properties that can be shadowed by `<form name="...">` or `<a id="...">` elements. Freeze/namespace globals and check `typeof` / `Object.prototype.hasOwnProperty`.
- **Service Worker hygiene:** Register Service Workers only from static, same-origin, immutable paths (`/sw.js`) with narrow `scope`, never from user-controlled query parameters or dynamic endpoints.
- **Prevent Client-Side Path Traversal (CSPT):** Never interpolate untrusted URL query/hash params directly into `fetch(`/api/v1/${param}`)` paths; validate IDs with strict regex (e.g., `/^[a-zA-Z0-9_-]{1,64}$/`) and `encodeURIComponent()`.

## 4. Security Headers, Clickjacking & Dependencies
- **Strict CSP & Framing:** Ship `Content-Security-Policy` with nonces/hashes (avoid `'unsafe-inline'` and `'unsafe-eval'`) and `frame-ancestors 'none'` (plus `X-Frame-Options: DENY`) to block Clickjacking.
- **No vulnerable CDN bundles (`JS-CVE-001`):** Audit third-party JS libraries (jQuery, DOMPurify, Lodash, Handlebars, Marked, Axios) against OSV/GHSA, self-host static assets, and pin Subresource Integrity (`integrity="sha384-..."`) if external CDNs are unavoidable.
- **Desktop/Electron (`IPC-001`):** Always set `nodeIntegration: false`, `contextIsolation: true`, and `sandbox: true` in `BrowserWindow` webPreferences.
