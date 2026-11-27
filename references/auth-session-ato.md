# Authentication, Session & Account Takeover (ATO) Prevention

**Scope:** Forgot-password flows, MFA/OTP, OAuth 2.0/OIDC, SAML/SSO, JWT, Session Cookies, Rate Limiting.
**Related WSS Rules:** `JWT-005`, `JWT-006`, `OAUTH-001`, `OAUTH-002`, `FW-003`, `CRYPTO-006`, `CRYPTO-007`, `HAR-COOKIE-001`.

## 1. Password Reset & Account Recovery
- **Constant responses:** Return identical HTTP status, message, and timing for existing and non-existing accounts to prevent user enumeration.
- **CSPRNG tokens only:** Generate reset tokens and OTPs with `secrets.token_urlsafe(32)`, `crypto.randomBytes(32)`, or PHP `random_bytes(32)` — NEVER `Math.random()`, `random.choice()`, or `rand()`.
- **Never leak tokens in responses:** Reset tokens must never appear in API JSON bodies, error messages, or URLs logged to analytics.
- **Pin reset link host:** Build password reset URLs from a hardcoded server configuration (`APP_BASE_URL`), NEVER from `req.headers.host` or `X-Forwarded-Host` (prevents Host Header Reset Poisoning).
- **Single-use & short TTL:** Store only the SHA-256 hash of the reset token, expire in <= 15 minutes, invalidate immediately after use, and revoke all existing active sessions on password change.

## 2. OAuth 2.0 / OIDC & SAML SSO
- **Mandatory `state` + PKCE (`S256`):** Never disable `state` validation (`OAUTH-001`); bind `state` to the user's browser session to prevent login CSRF and account linking attacks.
- **Exact `redirect_uri` matching:** Never allow wildcards (`*`), regex prefix matches, or unvalidated open redirects on OAuth callbacks (`OAUTH-002`).
- **SAML Signature Enforcement (`FW-003`):** Always enforce `wantAssertionsSigned: true` and `wantResponseSigned: true`. Reject XML comments inside `<NameID>` and validate signatures against the exact DOM node used for user extraction (prevents XML Signature Wrapping).

## 3. JWT & Session Hardening
- **Explicit algorithm allowlist:** Pin asymmetric (`RS256`/`ES256`/`EdDSA`) or symmetric (`HS256`) algorithms explicitly during verification; reject `alg: none`.
- **Untrusted JWT headers (`JWT-005`, `JWT-006`):** Never fetch `jku`/`x5u` URLs dynamically without a strict pinned allowlist, and never pass `kid` into filesystem paths or SQL queries.
- **Constant-time comparison (`CRYPTO-007`):** Always verify HMACs, webhook signatures, API keys, and reset tokens with `hmac.compare_digest` (Python), `crypto.timingSafeEqual` (Node.js), or `hash_equals` (PHP).
- **Session cookies:** Enforce `HttpOnly; Secure; SameSite=Lax` (or `Strict`), rotate session IDs on login/privilege change, and invalidate sessions server-side on logout.
- **Brute-force & OTP protection:** Apply per-account + per-IP rate limiting and lockout/backoff on login, MFA verification, and password reset endpoints.
