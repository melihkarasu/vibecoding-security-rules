# Business Logic, Race Conditions & File Upload Security

**Scope:** TOCTOU / Concurrency, Financial Precision, Idempotency, Workflow Integrity, CAPTCHA & Rate Limiting, Safe File Uploads.
**Related WSS Rules:** `business_logic_engine.py`, `CRYPTO-006`, `HAR-ERR-001`.

## 1. Concurrency & Race Condition Prevention (TOCTOU)
- **Database-level atomic updates:** Never implement balance checks, coupon redemptions, or quota consumption as separate `SELECT` then `UPDATE` queries outside a lock. Use atomic conditional SQL (`UPDATE wallets SET balance = balance - ? WHERE id = ? AND balance >= ?`), `SELECT ... FOR UPDATE`, or `SERIALIZABLE` transactions.
- **Enforce `Idempotency-Key` with unique constraints:** Store processed idempotency keys in a `UNIQUE` database column within the same transaction as the state change so concurrent duplicate requests fail safely.

## 2. Numeric, Currency & Workflow Integrity
- **Server-side pricing & minor units:** Always compute totals, discounts, taxes, and fees on the server using authoritative catalog prices. Represent money as exact integers (cents/kuruş) or `Decimal` — never binary floating-point (`float`/`double`), and reject `<= 0`, `NaN`, or `Infinity` quantities.
- **State-machine enforcement:** Validate required prior states on every step of multi-step workflows (checkout, KYC, approval) rather than trusting client-supplied step flags or hidden form fields.

## 3. Anti-Automation, Rate Limiting & CAPTCHA
- **Server-side verification only:** Reject requests if the CAPTCHA token field is missing, empty, reused, or tied to a different hostname/action. Never skip validation when an optional header or alternate content-type is sent.
- **Layered throttling:** Apply rate limits by authenticated user ID + IP + target resource (e.g., email/phone being targeted for OTP/reset) using sliding windows in Redis/atomic stores.

## 4. Safe File Uploads
- **Strict allowlist + magic bytes:** Validate both extension and actual file header (magic bytes) against a narrow allowlist; reject double extensions and sanitize filenames to generated UUIDs (never use client filenames in filesystem paths).
- **Serve outside executable webroot:** Store uploads in private object storage (S3/GCS) or outside `/public`/`/wwwroot`, serve with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, and never serve user-uploaded `.svg` or `.html` inline on the application origin.
- **Re-encode images & disable XML external entities:** Strip EXIF/metadata via image re-encoding (Pillow/Sharp) and disable DTD/XXE when parsing uploaded DOCX/XLSX/XML/SVG files.
