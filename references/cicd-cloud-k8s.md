# CI/CD, Cloud IAM, Containers & Supply Chain Security

**Scope:** GitHub Actions, OIDC Trust Policies, Terraform / IaC, AWS/GCP IAM, Docker & Kubernetes, Dependency Confusion.
**Related WSS Rules:** `CICD-001`..`004`, `CLOUD-001`..`004`, `K8S-001`..`008`, `SUP-001`, `SUP-002`.

## 1. GitHub Actions & CI/CD Hardening
- **Avoid `pull_request_target` with untrusted checkout:** Never check out fork PR code under `pull_request_target` where repository secrets and write tokens are exposed (PwnRequest).
- **Never interpolate `${{ github.event.* }}` into `run:` shell scripts:** Pass untrusted metadata (PR title, branch name, comment body) through `env:` variables and quote them (`"$PR_TITLE"`).
- **Least-privilege tokens (`CICD-003`):** Set top-level `permissions: read-all` (or `contents: read`) and grant elevated scopes only to the single job that requires them.
- **Pin third-party actions by commit SHA (`CICD-004`):** Pin external actions to full 40-character commit SHAs (`uses: vendor/action@<40-hex-sha>`) instead of mutable `@main` or `@v1` tags.
- **Scoped OIDC trust (`CLOUD-004`):** Restrict cloud IAM OIDC `sub` claims to exact `repo:org/repo:ref:refs/heads/main` or named deployment environments — never `repo:*`.

## 2. Cloud IAM & Infrastructure as Code (Terraform / IaC)
- **Block public object storage (`CLOUD-001`):** Enforce S3 `block_public_acls = true`, `block_public_policy = true`, `ignore_public_acls = true`, `restrict_public_buckets = true` and private ACLs by default.
- **Require IMDSv2 (`CLOUD-002`):** Set `http_tokens = "required"` and `http_put_response_hop_limit = 1` on EC2 instances to neutralize SSRF-to-IAM credential theft.
- **No wildcard IAM (`CLOUD-003`):** Replace `"Action": "*"` and `"Resource": "*"` with narrowly scoped actions, resource ARNs, and explicit `aws:SourceAccount` / `ExternalId` conditions on `sts:AssumeRole` (confused-deputy defense).

## 3. Containers & Kubernetes
- **Never mount `/var/run/docker.sock` (`K8S-006`):** Use isolated TLS `docker:dind` or rootless BuildKit instead of exposing the host Docker daemon.
- **Non-root & minimal capabilities:** Set `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities: { drop: ["ALL"] }`, and forbid `privileged: true`, `hostPID`, `hostNetwork`, `hostIPC` (`K8S-007`).
- **RBAC discipline (`K8S-008`):** Ban `verbs: ["*"]` and `cluster-admin` bindings for application workloads.

## 4. Supply Chain & Dependency Confusion (`SUP-001`, `SUP-002`)
- **Python pip:** Avoid `--extra-index-url` and `--trusted-host` (which allow public PyPI package squatting); use `--index-url` pointing to a private mirroring proxy or hash-pinned `requirements.txt`.
- **Node.js npm:** Inspect `postinstall`/`preinstall` scripts, commit lockfiles, and run `npm ci --ignore-scripts` in untrusted CI contexts.
