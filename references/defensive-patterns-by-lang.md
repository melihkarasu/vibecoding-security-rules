# Defensive Secure Coding Patterns by Language

**Scope:** Ready-to-use safe idioms for Python, TypeScript/JavaScript, PHP, Go, Java, C#, and Rust.
**Related WSS Rules:** `SQLI-*`, `CMD-*`, `SSRF-*`, `CRYPTO-006`, `CRYPTO-007`, `FW-004`, `LARAVEL-*`, `NEXT-*`.

## 1. Python
```python
import hmac, secrets, sqlite3, subprocess

# Parameterized SQL (NEVER f-string or %)
cur.execute("SELECT id, email FROM users WHERE id = ? AND tenant_id = ?", (user_id, tenant_id))

# Safe subprocess (shell=False, list args, strict allowlist)
subprocess.run(["/usr/bin/git", "status", "--porcelain"], check=True, shell=False, timeout=10)

# CSPRNG token + constant-time verify
token = secrets.token_urlsafe(32)
valid = hmac.compare_digest(expected_hmac, provided_hmac)

# Safe YAML (NEVER yaml.load without SafeLoader, NEVER pickle.loads on untrusted data)
import yaml
data = yaml.safe_load(raw_yaml)
```

## 2. TypeScript / JavaScript (Node.js & Browser)
```ts
import crypto from "node:crypto";
import { execFile } from "node:child_process";

// CSPRNG + timingSafeEqual
const resetToken = crypto.randomBytes(32).toString("base64url");
const ok = a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

// Safe process invocation (no shell interpolation)
execFile("git", ["diff", "--name-only", baseRef], { timeout: 10_000 }, cb);

// Safe browser DOM & postMessage
el.textContent = untrustedText; // or el.setHTML(html) / DOMPurify.sanitize(html)
window.addEventListener("message", (event) => {
  if (event.origin !== "https://trusted.example.com") return;
  handleVerifiedMessage(event.data);
});
```

## 3. PHP / Laravel
```php
// PDO prepared statements with native prepares
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
$stmt = $pdo->prepare("SELECT id FROM orders WHERE id = :id AND user_id = :uid");
$stmt->execute([':id' => $id, ':uid' => $authUserId]);

// Laravel Eloquent mass assignment protection (NEVER $guarded = [])
protected $fillable = ['name', 'bio'];

// CSPRNG + constant-time verify + JSON instead of unserialize()
$token = bin2hex(random_bytes(32));
$isValid = hash_equals($expectedSig, $providedSig);
$payload = json_decode($rawJson, true, 512, JSON_THROW_ON_ERROR);
```

## 4. Go, Java, C# & Rust Essentials
- **Go:** Use `database/sql` placeholders (`$1`/`?`), `crypto/rand`, `subtle.ConstantTimeCompare`, and explicit WebSocket `CheckOrigin` allowlist.
- **Java / Spring:** Use JPA/JDBC bound parameters, `SecureRandom`, `MessageDigest.isEqual`, disable XML DTD (`disallow-doctype-decl`), expose only `health,info` Actuator endpoints.
- **C# / ASP.NET:** Use EF Core parameterized queries, `RandomNumberGenerator.GetBytes`, `CryptographicOperations.FixedTimeEquals`, keep `enableViewStateMac="true"`, and never use `BinaryFormatter`.
- **Rust:** Avoid unnecessary `unsafe` blocks on untrusted input parsers, use `sqlx`/`diesel` bound queries, `subtle::ConstantTimeEq`, and `rand::rngs::OsRng`.
