# VulnTracker Security Assessment Findings

**Assessment date:** 3 November 2026
**Assessment type:** Initial security scan baseline
**Application:** VulnTracker (FastAPI and Express)

## 1. Executive overview

Six scanner reports were generated across four security assessment categories.

| Category | Tool | Result |
|---|---|---|
| SAST | Bandit | 40 findings |
| SAST | Semgrep | 6 findings |
| SCA | pip-audit | 8 affected packages; duplicate advisory records exist |
| SCA | npm audit | 11 vulnerabilities |
| Container | Trivy | 185 OS findings and 47 Python-package findings |
| IaC | Checkov | 89 passed, 0 failed, 0 skipped |

These are initial scan results. Findings must be validated for exploitability and applicability before being treated as confirmed exploitable vulnerabilities.

## 2. SAST findings

### 2.1 JWT algorithm configuration

- **Tool:** Semgrep
- **Rule:** python.jwt.security.jwt-none-alg.jwt-python-none-alg
- **Severity:** ERROR (scanner classification)
- **Location:** app/auth.py, line 38
- **Source:** Existing application code (starter code)
- **Description:** JWT verification may accept the `none` algorithm.
- **Business impact:** An attacker could potentially forge authentication tokens and impersonate users if this behavior is exploitable.
- **Recommended remediation:** Explicitly allow only the intended secure signing algorithm during JWT verification. Add negative tests for unsigned tokens and unexpected algorithms.

### 2.2 SQL query construction

- **Tools:** Bandit and Semgrep
- **Rules:** B608 and avoid-sqlalchemy-text
- **Severity:** Medium (Bandit); ERROR (Semgrep)
- **Location:** app/database.py, lines 23 and 28
- **Source:** Existing application code (starter code)
- **Description:** String-based SQL construction and SQLAlchemy text usage were flagged.
- **Business impact:** If untrusted input reaches the query, an attacker could manipulate database queries, potentially exposing or modifying application data.
- **Recommended remediation:** Use SQLAlchemy parameterized expressions and bound parameters. Validate inputs and avoid concatenating untrusted values into SQL statements.

### 2.3 Credentials written to application logs

- **Tool:** Semgrep
- **Rule:** python.lang.security.audit.logging.logger-credential-leak
- **Severity:** WARNING (scanner classification)
- **Locations:** app/main.py, lines 153 and 156
- **Source:** Existing application login functionality (starter code)
- **Description:** Login logging statements may include submitted passwords.
- **Business impact:** Credentials could be exposed through application logs, log aggregation platforms, or users with log access.
- **Recommended remediation:** Never log passwords, access tokens, or other authentication secrets. Log usernames and authentication outcomes only, with appropriate masking where needed.

### 2.4 Hardcoded credentials and test-only findings

- **Tool:** Bandit
- **Severity:** Low (scanner classification)
- **Locations:** app/config.py and tests/test_api.py
- **Source:** Existing application configuration and test code (starter code)
- **Description:** Bandit flagged hardcoded credential-like values in configuration and tests. It also reported Python assert statements in tests.
- **Business impact:** Real credentials stored in source code could be exposed through repository access. Test assertions are generally expected in test code and are not equivalent to production security vulnerabilities.
- **Recommended remediation:** Move production secrets into environment variables or a secrets manager. Rotate any real credentials that have been committed or exposed. Keep test credentials isolated and non-production. Review assert findings in the context of test execution.

Bandit also flagged the word `bearer` in app/main.py as a possible hardcoded password. This appears to be a credential-pattern false positive and should be manually reviewed.

### 2.5 Missing CSRF protection

- **Tool:** Semgrep
- **Rule:** javascript.express.security.audit.express-check-csurf-middleware-usage
- **Severity:** INFO (scanner classification)
- **Location:** notify/src/index.js, line 6
- **Source:** Existing notification service (starter code)
- **Description:** No CSRF middleware was detected.
- **Business impact:** If browser cookies or other automatically attached credentials are used for state-changing requests, cross-site request forgery may be possible.
- **Recommended remediation:** Determine whether the service uses browser-based cookie authentication. If applicable, implement suitable CSRF protection, SameSite cookie settings, and origin validation.

### 2.6 Mass assignment / unsafe object assignment

- **Tool:** Semgrep
- **Rule:** javascript.express.security.express-data-exfiltration
- **Severity:** WARNING (scanner classification)
- **Location:** notify/src/index.js, line 26
- **Source:** Existing notification service (starter code)
- **Description:** Object.assign uses user-controlled data in a way that may permit unintended property modification.
- **Business impact:** An attacker could potentially modify fields that should be controlled by the application.
- **Recommended remediation:** Use explicit field allowlists and construct request objects from validated properties. Avoid copying unrestricted user-controlled objects into sensitive application objects.

## 3. Software composition analysis (SCA)

### 3.1 Python dependencies

- **Tool:** pip-audit
- **Severity:** The extracted pip-audit output does not provide severity values; do not infer severity from advisory counts.
- **Source:** Existing Python dependency pins (starter code)
- **Affected packages:** FastAPI, python-jose, python-multipart, cryptography, pytest, AnyIO, Starlette, and ecdsa.
- **Description:** Multiple installed dependency versions have published security advisories. Some advisories have duplicate records in the report.
- **Business impact:** Vulnerable dependencies can expose the API to denial of service, authentication weaknesses, or other security issues depending on the affected code paths and vulnerability conditions.
- **Recommended remediation:**
  - Review compatible patched FastAPI and Starlette versions together.
  - Upgrade python-jose to a secure supported version and review advisories without a listed fix.
  - Upgrade python-multipart to a patched version.
  - Upgrade cryptography to a supported patched release.
  - Review the ecdsa advisory because the report does not list a fix version.
  - Upgrade test dependencies such as pytest and AnyIO as appropriate.
  - Run the complete test suite after dependency changes.

### 3.2 Node.js dependencies

- **Tool:** npm audit
- **Severity summary:** 1 critical, 5 high, 2 moderate, and 3 low.
- **Source:** Existing notification service dependencies (starter code)
- **Affected packages:** axios, body-parser, cookie, express, follow-redirects, path-to-regexp, proxy-addr, qs, send, serve-static, and uuid.
- **Business impact:** Vulnerable HTTP and Express dependencies may expose the notification service to request-handling attacks, denial of service, or other dependency-specific risks.
- **Recommended remediation:**
  - Upgrade Express to the reported patched 4.22.3 release, subject to compatibility testing.
  - Upgrade axios to the reported 0.21.4 release or a later supported patched version.
  - Review transitive dependency updates and regenerate package-lock.json.
  - Review the uuid major-version upgrade separately for compatibility.
  - Run npm test and npm audit again after remediation.

## 4. Container image findings

- **Tool:** Trivy
- **Image:** vulntracker:task2
- **Base distribution detected:** Debian 13.7
- **Source:** Container base image and installed Python packages
- **OS findings:** 185
  - Unknown: 7
  - Low: 61
  - Medium: 72
  - High: 45
  - Critical: 0
- **Python package findings:** 47
  - Includes critical findings in AnyIO and python-jose, as well as high and medium findings in other dependencies.
- **Business impact:** Vulnerable operating-system libraries and Python packages may expose the running application to known security weaknesses.
- **Recommended remediation:**
  - Rebuild using an updated, supported and digest-pinned base image.
  - Update operating-system packages where supported.
  - Upgrade vulnerable Python dependencies.
  - Keep test-only packages out of production images where possible.
  - Rescan the rebuilt image and compare the results.

The Trivy findings are scanner detections, not proof that every listed vulnerability is exploitable in the application. Validate package usage, reachability, and available fixes.

## 5. Infrastructure as Code findings

- **Tool:** Checkov 3.4.3
- **Framework:** Kubernetes
- **Files:** k8s/deployment.yaml and k8s/network-policy.yaml
- **Source:** Deployment configuration created for this assignment
- **Initial findings:** 4 failed checks.
- **Latest scan:** 89 passed, 0 failed, 0 skipped.

The following initial findings were addressed:

| Check | Initial issue | Remediation |
|---|---|---|
| CKV_K8S_21 | Default namespace used | Created dedicated vulntracker namespace |
| CKV_K8S_15 | Image pull policy not Always | Set imagePullPolicy to Always |
| CKV_K8S_43 | Image not pinned by digest | Used registry image digest |
| CKV2_K8S_6 | Missing NetworkPolicy | Added ingress NetworkPolicy |

The current scan demonstrates that the scanned Kubernetes configuration passes these Checkov policies. Runtime deployment and network connectivity still require separate validation.

## 6. Starter code versus new feature

The findings above primarily concern existing application and notification-service code, existing dependencies, and the initial container base image.

The Kubernetes deployment and NetworkPolicy findings relate to deployment artifacts created for this assignment.

No scanner result in this baseline conclusively identifies a vulnerability specifically introduced by the new shared-report-link feature. This does not prove that the feature is free of security defects; it still requires targeted code review and security testing.

## 7. Evidence files

All raw scanner reports are stored under `reports/`:

- reports/sast.bandit.json
- reports/sast.semgrep.json
- reports/sca.pip-audit.json
- reports/sca.npm-audit.json
- reports/container.trivy.json
- reports/iac.checkov.json

## 8. Assessment conclusion

The initial assessment identified application-level security concerns, vulnerable Python and Node.js dependencies, and container image vulnerabilities. The Kubernetes static configuration findings have been remediated, with the latest Checkov scan reporting 89 passed and zero failed checks.

Application code, dependency versions, and the container image still require remediation and repeat scanning. Findings should only be marked resolved after the relevant fixes are implemented and verified.
