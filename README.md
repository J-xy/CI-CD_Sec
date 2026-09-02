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

## Runtime Configuration

The application reads its AWS credential from the environment and **refuses to start without it** — an unset variable raises at import rather than falling back to a default, so a misconfigured deployment fails loudly instead of running half-credentialed.

| Variable | Required | Notes |
| :--- | :--- | :--- |
| `AWS_SECRET_ACCESS_KEY` | yes | Injected at run time. Never a build arg. |

```bash
docker run -e AWS_SECRET_ACCESS_KEY=... demo-app:latest
```

From a workflow, map the repository secret straight into the container's environment:

```yaml
- name: Run application
  run: docker run -e AWS_SECRET_ACCESS_KEY=${{ secrets.AWS_SECRET_ACCESS_KEY }} demo-app:latest
```

Pass it with `-e` at run time, never with `--build-arg`: build arguments are recorded in image metadata and recoverable with `docker history`, which would bake the credential into a distributable artifact — the same class of exposure as committing it.

## Known Coverage Gaps

Every gap below was established by running the tools against this repo's fixtures, not inferred from documentation. They are retained deliberately: a pipeline that only demonstrates its successes teaches the wrong lesson.

### Gitleaks goes blind once a secret reaches `main`

`app/app.py:12` held a planted AWS secret key. It has been remediated — the value now loads from `AWS_SECRET_ACCESS_KEY` at runtime and the process refuses to start without it — but the episode is worth recording, because for as long as that literal sat on `main` the **Gitleaks job passed on every subsequent pull request.**

`gitleaks-action` on a `pull_request` event scans only the commits belonging to that PR, not the checked-out tree. Once a credential lands on the default branch it is never again "new" in any later diff, so the gate stays green while the secret stays in the repo. Diff-scoped secret scanning answers *"did this PR add a secret?"* — never *"does this repo contain one?"*

Trivy caught it throughout, because it scans the built image filesystem rather than a diff:

```
/app/app.py (secrets)
Total: 1 (CRITICAL: 1)
CRITICAL: AWS (aws-secret-access-key)  /app/app.py:12
```

Two independent stages, one blind, one not — which is the entire argument for defence in depth over a single trusted gate. Never infer from a green secret gate that a repo is clean; infer only that this diff added nothing new.

**Deleting the line does not undo the exposure.** The value remains in `main`'s git history and can be recovered from any clone. Source removal stops the leak growing; only rotating the credential at the provider ends it. The key planted here was synthetic, so there was nothing to rotate — against a real one, rotation is the first step and the code change is the second.

### Silence is not a pass

| Fixture | Missed by | Caught by | Why the miss |
| :--- | :--- | :--- | :--- |
| Planted AWS key on `main` (now remediated) | Gitleaks (post-merge) | Trivy (image scan) | Diff-scoped scan; not "new" in later PRs |
| Canonical AWS docs key | Gitleaks | — | `example` is a `generic-api-key` stopword |
| `password = "SuperSecret123!"` (`infra/main.tf:59`) | Gitleaks, Checkov `--framework secrets` | — | Entropy-based rules; dictionary-like passwords fall below threshold |
| Bare `aws_s3_bucket` | Checkov | tfsec / `trivy config` | Checkov's S3 rules target `aws_s3_bucket_public_access_block`; absent resource means nothing to evaluate |

Checkov and tfsec overlap only ~40% on `infra/main.tf` and neither is a superset: Checkov is materially stronger on IAM behavioural checks, tfsec is the only S3 coverage here. Semgrep and tfsec ship no secret-detection rules at all.

Two operating rules follow. **A red check has usually meant a broken scanner, not a finding** — every red build in this repo's history traced to a misconfiguration (zero commits scanned, a 403, a missing SARIF input, a nonexistent action) rather than a detection. Read the log before trusting either colour. And **demo secrets must be fake but not recognisably fake**, or the stopword lists will quietly swallow them.
