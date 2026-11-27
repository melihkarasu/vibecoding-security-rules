# Framework & 2026 Runtime Security Guide

**Scope:** Next.js/React, Laravel/PHP (2026 Advisories), Node.js (Oct 2026 Advisories), Spring Boot/Java, ASP.NET, Deserialization.
**Related WSS Rules:** `NEXT-001`, `NEXT-002`, `LARAVEL-001`..`003`, `FW-001`..`004`, `PHP-ADV-*`, `NODE-ADV-*`, `MYSQL-ADV-*`.

## 1. Next.js & React App Router
- **Server Actions (`"use server"`) are public POST endpoints:** Authenticate and authorize inside EVERY Server Action and validate all inputs with Zod before touching the database (`NEXT-002`). Never rely solely on `middleware.ts` for authorization.
- **Image Optimizer SSRF (`NEXT-001`):** Never use wildcard `hostname: "**"` or `"*"` in `images.remotePatterns` / `domains`. Pin explicit trusted hostnames and paths.
- **Server Component boundary:** Never pass secrets, database credentials, or full ORM user objects (containing password hashes/tokens) as props to `"use client"` components.

## 2. Laravel & PHP (Including 2026 Security Advisories)
- **Mass Assignment (`LARAVEL-001`):** Never set `$guarded = []` on Eloquent models; declare explicit `$fillable` allowlists.
- **Blade XSS (`LARAVEL-002`):** Use escaped `{{ $var }}` by default; forbid `{!! $userInput !!}` unless sanitized server-side with HTMLPurifier.
- **Deserialization (`LARAVEL-003`):** Never pass user input to `unserialize()`; use `json_decode()`. If legacy deserialization is unavoidable, enforce `['allowed_classes' => false]` and block `phar://` stream wrappers.
- **2026 PHP & MySQL Runtime Hygiene:** Keep PHP patched against the 2026 `php2shell` (CVE-2026-109618/109619/115560) and Nov 2026 UAF/FPM smuggling/session RCE advisories; pin `mysqli`/`PDO` prepared statements (`ATTR_EMULATE_PREPARES => false`) and stay current on Oracle MySQL CPU releases.
- **WordPress & Plugin Object Injection (CVE-2026-134481 - CVSS 9.8):** In WordPress environments and membership plugins (e.g. Ultimate Member `<= 2.14.1`), never pass user-supplied request parameters, headers, or serialized cookies directly into `unserialize()`. Always upgrade `ultimate-member >= 2.14.2` and enforce JSON serialization with strict schema validation.

## 3. Node.js (Including Oct 2026 Security Releases)
- Stay patched past the Oct 2026 Node.js security releases (including CVE-2026-111497 Brotli RCE and HTTP parser fixes).
- Enforce `insecureHTTPParser: false`, set request body size limits, and avoid `child_process.exec()` with template literals (use `execFile()` with an argument array).

## 4. Spring Boot / Java & ASP.NET
- **Spring Boot Actuator (`FW-001`):** Never expose `management.endpoints.web.exposure.include=*` publicly. Expose only `health,info` on a dedicated internal management port with authentication. Avoid user input in Spring SpEL expressions.
- **ASP.NET ViewState (`FW-002`):** Never set `enableViewStateMac="false"` or `viewStateEncryptionMode="Never"`. Protect `machineKey` values as high-value secrets and disable `trace.axd` / `elmah.axd` in production.
- **Cross-Language Deserialization (`FW-004`):** Ban `ObjectInputStream`, `.NET BinaryFormatter`, Python `pickle.loads`, and `yaml.load` without `SafeLoader` on any untrusted data; standardize on JSON / Protocol Buffers with schema validation.
