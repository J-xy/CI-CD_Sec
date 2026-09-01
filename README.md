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
| **Container Scan** | Trivy | Base image & OS packages | **Hard Gate (CRITICALs)** | SARIF |
| **SBOM Generation** | Syft | Ephemeral build layers | Artifact Retention | CycloneDX JSON |

## Pipeline Architecture

1. **Trigger:** Runs on `push` and `pull_request` to `main`, plus a weekly `schedule` (cron) to catch newly disclosed zero-days in existing baselines.
2. **Hardening:** GitHub Actions default permissions are explicitly revoked (`contents: read` at the top level), granting only `security-events: write` precisely where SARIF uploads occur.
3. **Multi-Stage Build:** Dockerfile utilizes a `builder` pattern and creates a non-root `appuser` to minimize runtime attack surface.