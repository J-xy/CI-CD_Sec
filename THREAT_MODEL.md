# Threat Model — CI-CD_Sec

Scope: the security pipeline in `.github/workflows/security.yml`, the GitHub repository that hosts it, and the fixtures it scans (`app/`, `infra/`).

Last reviewed 2026-09-01 against `main` at commit `621d4cc`. Every control claim below was verified by running the tools and reading the resulting logs, not inferred from documentation.

**`main`'s pipeline is currently broken and running no checks at all — see §3.8 before anything else.**

**This document describes `main` as it stands.** Several findings below have fixes already prepared in PR #5 (`feature/remediation-fixes`); each says so explicitly. Re-review when that PR merges — §3.3 in particular changes character.

---

## 1. The central distinction

This repository contains deliberately vulnerable code. That code is **not the threat**.

`infra/main.tf` declares a world-open security group, a wildcard `*:*` IAM policy, and a public unencrypted RDS instance with a hardcoded password. None of it is ever applied — no job runs `terraform plan` or `apply`, no AWS credentials exist in the repository, and no state backend is configured. `app/app.py` has SQL injection, command injection, and `debug=True` bound to `0.0.0.0`. It is built into an image for scanning and never deployed or exposed.

These are **scanner fixtures**. Their risk is latent and materialises only if someone copies them into a real project.

The live attack surface is the **pipeline itself**: a public repository whose workflow checks out untrusted code, builds it, and executes third-party actions on GitHub-hosted runners. That is where this document spends its attention.

---

## 2. Assets and trust boundaries

| Asset | Why it matters |
| :--- | :--- |
| `GITHUB_TOKEN` issued per job | Can write to the repo and to code scanning if over-scoped |
| Repository contents and history | Public; anything committed is permanent and world-readable |
| The workflow definition | Whoever edits it controls what executes in CI |
| Code scanning results | Suppressing or poisoning these hides real findings |
| Branch protection configuration | The only thing standing between a PR and `main` |

Trust boundaries, in decreasing order of trust:

```
GitHub Actions runner (executes arbitrary repo code)
  ├── workflow definition ......... trusted, but editable via PR
  ├── repository source ........... UNTRUSTED on pull_request from a fork
  ├── third-party actions ......... UNTRUSTED, and mostly floating refs (§3.1)
  └── base images from Docker Hub . UNTRUSTED, and currently stale (§3.5)
```

The pipeline triggers on `pull_request`, **not** `pull_request_target`. This is the single most important control here: fork PRs run with a read-only token and no access to repository secrets. Changing that one word would expose secrets to any stranger who opens a PR.

---

## 3. Threats

Ordered by exploitability against `main` as it stands. **§3.8 is the one to read first** — the pipeline is not currently running on the default branch, which conditions everything else here.

### 3.1 Supply chain — mutable action references

Four steps resolve to moving branches:

```
bridgecrewio/checkov-action@master
aquasecurity/trivy-action@master     (×3 — FS scan, image scan, blocking gate)
```

Every run pulls whatever those branches contain at that moment. Compromise of an upstream repository, or of any maintainer account, results in attacker-controlled code executing in this pipeline with the job's token — with no change to this repository and nothing to review. **No action is pinned to an immutable reference.**

Tag pins (`actions/checkout@v4`, `gitleaks-action@v2`, `codeql-action@v3`, `sbom-action@v0`, `setup-terraform@v3`, `upload-artifact@v4`) are better but still mutable: a tag can be force-moved to a different commit.

*STRIDE: Tampering, Elevation of Privilege.* **Highest-severity item in this model** — the only finding here with a plausible path to arbitrary code execution. (§3.8 outranks it on *priority* only because the pipeline is down right now; this one outranks everything on impact.)

Mitigation: pin every action to a full commit SHA with the version in a trailing comment. PR #5 pins the three `trivy-action` uses to `v0.36.0`, which narrows this but does not close it; `checkov-action@master` survives that PR untouched.

### 3.2 The advertised hard gate does not gate

`README.md` describes the Trivy container scan as a **Hard Gate (CRITICALs)**. Branch protection tells a different story:

```
required_status_checks: ["Gitleaks Secret Scanner", "Semgrep SAST"]
required_pull_request_reviews: null
enforce_admins: false
```

Trivy and Checkov are **not required checks**. A pull request whose container scan fails on a CRITICAL vulnerability remains mergeable — that was the literal state of PR #5 for most of its life (`mergeStateStatus: UNSTABLE`, both required checks green, merge button live). The gate produces a red mark that nothing enforces.

Compounding it: `required_pull_request_reviews` is null, so no human review is required at all, and `enforce_admins: false` means the repository owner bypasses even the two required checks. For a single-maintainer demo those are reasonable trades; they are documented here so they are decisions rather than assumptions.

*STRIDE: Elevation of Privilege.* Mitigation: either add `Trivy Container Scan` to the required contexts, or correct the README to call it advisory. The gap between documented and actual enforcement is the real defect — a reader currently believes CRITICALs cannot reach `main`, and they can.

### 3.3 Token scoping is currently correct — and a pending PR regresses it

A job-level `permissions` block sets every unlisted scope to `none`, so any job with a block must restate `contents: read` for its checkout. On `main` today, all three jobs that declare a block get this right:

| Job | On `main` | After PR #5 |
| :--- | :--- | :--- |
| `sast-scanning` | `contents: read`, `security-events: write` | unchanged |
| `iac-scanning` | `contents: read`, `security-events: write` | **`security-events: write` only** |
| `container-scanning` | `contents: read`, `security-events: write` | **`security-events: write` only** |

`secret-scanning` and `sbom-generation` declare no block and inherit the top-level `contents: read`, which is correct.

PR #5 removes `contents: read` from two jobs. Those jobs continue to pass **only because this repository is public** — `actions/checkout` clones a public repository without authentication. Making the repository private would break both at checkout, with a failure whose cause is not obvious from the error.

*STRIDE: Denial of Service (availability of the control).* Mitigation: restore the two declarations before merging PR #5. Noted here because the regression is easy to miss in review — the same PR adds a comment to `sast-scanning` explaining precisely the rule it then breaks elsewhere.

### 3.4 Untrusted code executes during the build

`docker build ./app` runs on every pull request, including from forks. A `Dockerfile` is a script: a malicious PR can add `RUN curl … | sh` and it executes on the runner before any scanner sees it. Scanning happens *after* the build, so no scanner can prevent this by design.

Blast radius is bounded by the `pull_request` trigger — read-only token, no secrets, ephemeral runner — so realistic impact is cryptomining or using the runner as an egress point, not repository compromise. It is not nothing.

*STRIDE: Elevation of Privilege.* Mitigation: require approval before running workflows for first-time contributors (a repository setting, not a workflow change).

### 3.5 Stale base image — three live CRITICALs

`app/Dockerfile` builds `FROM python:3.9-slim`. Python 3.9 is EOL, so that tag is no longer rebuilt and ships progressively staler Debian packages. Measured on the current image:

```
libssl3t64              CVE-2026-31789  CRITICAL  3.5.1-1+deb13u1 → 3.5.5-1~deb13u2
openssl                 CVE-2026-31789  CRITICAL
openssl-provider-legacy CVE-2026-31789  CRITICAL
```

These are fixable and unfixed, so the Trivy blocking gate exits 1 on every run of `main` — but per §3.2 nothing enforces that exit code, so it blocks nothing.

A base image tag is only as current as its last rebuild. Two independent controls are needed: bump the base *and* run `apt-get upgrade` at build time, the latter covering the window between Debian publishing a patch and the registry republishing the tag. Verified: `apt-get upgrade` alone clears all three findings even on 3.9-slim, because it pulls from Debian's security repo rather than from the image tag — but it leaves the EOL Python runtime unpatched and costs +16 MB. They are complements, not alternatives.

*STRIDE: Tampering (via known vulnerability).* Fixed in PR #5 by both mechanisms.

### 3.6 Secrets in version control

`app/app.py:12` hardcodes an AWS secret key. It is a fabricated value with no live credential behind it, so there is no active exposure — but the repository is public, so it is world-readable and permanent.

Two properties make this the most instructive finding here. First, the secret gate does not catch it (§4). Second, **deleting the line will not retract it**: the value stays in `main`'s history and is recoverable from any clone. Only rotation at the provider ends a real leak; source removal merely caps its growth.

*STRIDE: Information Disclosure.* PR #5 replaces the literal with `os.environ.get("AWS_SECRET_ACCESS_KEY")` and a fail-fast raise. The history remains — purging it requires a rewrite and a temporary lift of branch protection, and is optional here only because the key is synthetic.

### 3.7 Fixture risk

The `infra/` and `app/` fixtures are safe where they sit and dangerous if copied. The wildcard IAM policy and the `0.0.0.0/0` SSH rule are exactly the shapes that get lifted into real modules. Mitigation is documentary: every fixture carries an inline `# RULE:` comment naming the check it exists to trip.

### 3.8 The pipeline on `main` does not run

**Every security control is currently inert on the default branch.** `main` at `621d4cc` produces:

```
X main Security Pipeline · 33549929436
X This run likely failed because of a workflow file issue.
```

`security.yml` ends with a duplicated `on:` block, a duplicated `permissions:` block, and — the fatal item — a SHA-pinning *example* pasted as live YAML rather than as a comment:

```yaml
# Instead of actions/checkout@v4
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

`uses:` is not a valid top-level workflow key, so GitHub rejects the file before any job starts. No gitleaks, no semgrep, no checkov, no trivy, no SBOM — since 2026-09-01T19:30.

This is invisible from the pull request view. A `pull_request` event evaluates the workflow from the PR's head, so a branch carrying a corrected file shows a full green run while `main` itself executes nothing. PR #5 has been green throughout on a workflow `main` cannot parse.

It is also the sharpest instance of this repository's own lesson (§4). A broken scanner reads as a red check. A broken *workflow* reads as no check at all — and an empty checks list is far easier to mistake for "nothing to report" than a red X is.

*STRIDE: Denial of Service (total loss of the control plane).* **Highest-priority item in this model.** Fixed in PR #5, which rewrites the file; merging it restores the pipeline. Validate before every push:

```bash
ruby -ryaml -e 'YAML.load_file(".github/workflows/security.yml")["jobs"].each_key{|k| puts k}'
```

Related: new jobs pasted into this file have landed at column 0 three times, parsing as top-level keys rather than jobs. The same class of error, caught earlier only by luck.

---

## 4. Control coverage — and where it is blind

The pipeline's value is in overlap. Its risk is in the gaps, all verified empirically:

| Fixture | Missed by | Caught by | Mechanism of the miss |
| :--- | :--- | :--- | :--- |
| `AWS_SECRET_KEY` on `main` | Gitleaks | Trivy (image scan) | `gitleaks-action` scans only a PR's own commits — once merged, never "new" again |
| Canonical AWS docs key | Gitleaks | — | `example` is a `generic-api-key` stopword |
| `password = "SuperSecret123!"` | Gitleaks, Checkov secrets | — | Entropy-based; dictionary-like passwords fall below threshold |
| Bare `aws_s3_bucket` | Checkov | tfsec / `trivy config` | Checkov's S3 rules target `aws_s3_bucket_public_access_block`; absent resource, nothing to evaluate |

**The first row is the most instructive finding in this repository.** The secret in §3.6 sits on `main` while the Gitleaks job passes on every pull request. Diff-scoped secret scanning answers *"did this PR add a secret?"* It never answers *"does this repository contain one?"* A permanently green secret gate is fully consistent with a credential sitting in the tree for months.

Trivy catches it, because it scans the built image filesystem rather than a diff. Two independent stages, one blind and one not — the entire argument for defence in depth over a single trusted gate.

Checkov and tfsec overlap roughly 40% on `infra/main.tf` and neither is a superset — Checkov is materially stronger on IAM behavioural checks, tfsec is the only S3 coverage present. Semgrep and tfsec ship no secret detection at all.

### Interpreting results

Two rules, both learned the hard way here:

**Red has usually meant a broken scanner, not a finding.** Every red build in this repository's history traced to misconfiguration — zero commits scanned, a 403, a missing SARIF input, an action that does not exist, a crashed runner — rather than a detection. Read the log before believing the colour.

**Green means "these tools found nothing," never "this is safe."** Silence from a scanner with no applicable rule is indistinguishable from silence from a clean scan — and *no checks at all*, as on `main` today (§3.8), is quieter still.

---

## 5. Residual risks

| Risk | Status | Rationale |
| :--- | :--- | :--- |
| Synthetic key in `main`'s history | Open | Fake credential; purge needs a history rewrite |
| `enforce_admins: false` | Accepted | Single-maintainer demo repository |
| No required PR review | Accepted | Same |
| Fixtures remain exploitable | By design | They are the demonstration |
| Node 20 and `codeql-action` v3 deprecations | Open | Warning now, breaking later |

---

## 6. Prioritised actions

1. **Merge PR #5 to restore the pipeline** (§3.8) — `main` currently runs no security checks at all. Nothing else in this list matters while that holds. #5 also clears §3.5 and §3.6.
2. **Restore `contents: read` on `iac-scanning` and `container-scanning`** (§3.3) — three lines, and best done inside #5 before it merges.
3. **Pin `checkov-action` and the three `trivy-action` uses to commit SHAs** (§3.1) — the only threat here with a plausible path to arbitrary code execution. PR #5 addresses only the Trivy half.
4. **Reconcile the gate with reality** (§3.2) — add `Trivy Container Scan` to the required contexts, or stop calling it a hard gate. Currently the README overstates enforcement.
5. **Require approval for first-time contributors' workflow runs** (§3.4).
6. **Address the Node 20 and CodeQL v3 deprecations** before they become failures.

Items 2–4 are each small and independently shippable.
