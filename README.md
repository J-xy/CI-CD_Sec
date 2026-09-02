# Portfolio DevSecOps Pipeline

A demonstrable, portfolio-grade CI/CD security pipeline designed to showcase continuous security integration, artifact generation, and pipeline hardening using GitHub Actions.

## Design Philosophy
Security in CI/CD fails when it creates unacceptable friction for developers. This pipeline is built on the philosophy of **"Start narrow, publish everything, ratchet as you go."** 
* **Visibility First:** All scanners (Secrets, SAST, IaC, Dependencies) run and upload SARIF data to the GitHub Security tab for asynchronous remediation.
* **Targeted Gating:** The pipeline only breaks the build for `CRITICAL` container vulnerabilities that have known fixes (`ignore-unfixed: true`). This prevents alert fatigue and bypass requests while stopping net-new critical regressions.
* **Supply Chain Readiness:** Generates and retains CycloneDX SBOMs on every build to accelerate zero-day reachability analysis.

## Security Toolchain Matrix

| Phase | Tool | Target | Enforcement | Output |
| :--- | :--- | :--- | :--- | :--- |
| **Secret Scanning** | Gitleaks | Hardcoded AWS keys, tokens | Advisory | Standard Out |
| **SAST** | Semgrep | SQLi, Command Injection (Python) | Advisory | SARIF |
| **IaC Scanning** | Checkov | Terraform misconfigurations | Advisory (Soft Fail) | SARIF |
| **Container Scan** | Trivy | Base image, OS packages, secrets in image | **Hard Gate (CRITICALs)** | SARIF |
| **SBOM Generation** | Syft | Ephemeral build layers | Artifact Retention | CycloneDX JSON |

## Pipeline Architecture

1. **Trigger:** Runs on `push` and `pull_request` to `main`, plus a weekly `schedule` (cron) to catch newly disclosed zero-days in existing baselines.
2. **Hardening:** GitHub Actions default permissions are explicitly revoked (`contents: read` at the top level), granting only `security-events: write` precisely where SARIF uploads occur.
3. **Multi-Stage Build:** Dockerfile utilizes a `builder` pattern and creates a non-root `appuser` to minimize runtime attack surface.

## Known Coverage Gaps

Every gap below was established by running the tools against this repo's fixtures, not inferred from documentation. They are retained deliberately: a pipeline that only demonstrates its successes teaches the wrong lesson.

### Gitleaks goes blind once a secret reaches `main`

`app/app.py:12` contains a planted AWS secret key. It sits on `main` today, and the **Gitleaks job passes on every subsequent pull request.**

`gitleaks-action` on a `pull_request` event scans only the commits belonging to that PR, not the checked-out tree. Once a credential lands on the default branch it is never again "new" in any later diff, so the gate stays green while the secret stays in the repo. Diff-scoped secret scanning answers *"did this PR add a secret?"* — never *"does this repo contain one?"*

Trivy still catches it, because it scans the built image filesystem rather than a diff:

```
/app/app.py (secrets)
Total: 1 (CRITICAL: 1)
CRITICAL: AWS (aws-secret-access-key)  /app/app.py:12
```

Two independent stages, one blind, one not — which is the entire argument for defence in depth over a single trusted gate. The secret is intentionally left in place so this divergence stays reproducible.

### Silence is not a pass

| Fixture | Missed by | Caught by | Why the miss |
| :--- | :--- | :--- | :--- |
| Planted AWS key on `main` | Gitleaks (post-merge) | Trivy (image scan) | Diff-scoped scan; not "new" in later PRs |
| Canonical AWS docs key | Gitleaks | — | `example` is a `generic-api-key` stopword |
| `password = "SuperSecret123!"` (`infra/main.tf:59`) | Gitleaks, Checkov `--framework secrets` | — | Entropy-based rules; dictionary-like passwords fall below threshold |
| Bare `aws_s3_bucket` | Checkov | tfsec / `trivy config` | Checkov's S3 rules target `aws_s3_bucket_public_access_block`; absent resource means nothing to evaluate |

Checkov and tfsec overlap only ~40% on `infra/main.tf` and neither is a superset: Checkov is materially stronger on IAM behavioural checks, tfsec is the only S3 coverage here. Semgrep and tfsec ship no secret-detection rules at all.

Two operating rules follow. **A red check has usually meant a broken scanner, not a finding** — every red build in this repo's history traced to a misconfiguration (zero commits scanned, a 403, a missing SARIF input, a nonexistent action) rather than a detection. Read the log before trusting either colour. And **demo secrets must be fake but not recognisably fake**, or the stopword lists will quietly swallow them.
