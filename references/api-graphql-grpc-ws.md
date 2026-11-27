# API, GraphQL, gRPC & WebSocket Security

**Scope:** REST APIs, GraphQL, Fintech Mutations, gRPC, WebSockets, CORS, HTTP Request Smuggling, Shadow APIs.
**Related WSS Rules:** `CLOUD-005`, `SMUG-001`, `NEXT-002`, `HAR-CORS-001`, `HAR-CORS-002`, `HAR-SHADOW-001`.

## 1. REST & Authorization (BOLA / IDOR / Mass Assignment)
- **Object-level authorization on every call:** Never trust client-supplied `user_id`, `account_id`, or `tenant_id` alone; scope every query with the authenticated subject (`WHERE id = ? AND owner_id = ?`).
- **Explicit schema allowlists:** Validate every request body with Zod/Pydantic/Valibot and pick only permitted fields before ORM `.create()` / `.update()`. Never pass raw `req.body` or `Object.fromEntries(formData)`.
- **Fail closed on exceptional input:** Reject malformed JSON, wrong field types, oversized payloads, and null bytes with generic `400`/`422` errors; never fall through to default/admin paths or expose stack traces (`HAR-ERR-001`).

## 2. GraphQL Hardening
- **Disable production introspection & playgrounds:** Turn off `introspection` and GraphiQL/Apollo Sandbox in production environments.
- **Depth, complexity & batching caps:** Enforce query `maxDepth` (e.g., <= 7), cost/complexity limits, and disable or strictly cap array query batching and alias multiplication.
- **Field-level & fintech authorization:** Enforce authorization inside resolvers (not just route middleware). For financial mutations (transfers, withdrawals, redemptions), enforce server-side decimal precision (`Decimal`/integer minor units), positive amount bounds, and atomic `Idempotency-Key` locks.

## 3. gRPC Security (`CLOUD-005`)
- **Enforce TLS / mTLS:** Never deploy `grpc.ServerCredentials.createInsecure()` or `grpc.insecure_channel()` in production.
- **Disable server reflection in production:** Turn off `reflection.enable_server_reflection()` outside local dev to avoid exposing internal service/method schemas.
- **Authenticate every RPC interceptor:** Validate bearer tokens or client certificates in a global unary + stream interceptor rather than per-handler checks.

## 4. WebSockets (CSWSH Prevention)
- **Strict `Origin` allowlist:** Validate the `Origin` HTTP header during WebSocket upgrade against an exact allowlist (never `CheckOrigin: return true` or `origins: "*"`).
- **Per-message auth & rate limits:** Authenticate the socket using short-lived tokens (not ambient cross-site cookies alone) and enforce message size + frequency limits.

## 5. CORS, Request Smuggling & Shadow Endpoints
- **No wildcard CORS with credentials:** Never combine `Access-Control-Allow-Origin: *` or blindly reflected `Origin` headers with `Access-Control-Allow-Credentials: true`.
- **Strict HTTP parsing (`SMUG-001`):** Keep `insecureHTTPParser: false` and reject conflicting `Content-Length` + `Transfer-Encoding` headers at both proxy and app tiers.
- **Hide shadow/debug endpoints (`HAR-SHADOW-001`):** Gate `/swagger`, `/openapi.json`, `/actuator`, `/graphiql`, `.js.map`, `.git`, and `.env` away from public traffic.
