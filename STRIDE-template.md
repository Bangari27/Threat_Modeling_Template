# 🏗️ STRIDE Threat Modeling Template

> Use this template for security design reviews of new features or systems.
> STRIDE = Spoofing · Tampering · Repudiation · Information Disclosure · Denial of Service · Elevation of Privilege

---

## SYSTEM OVERVIEW

**System/Feature Name:** [e.g., Experiment Data API]
**Date:** [YYYY-MM-DD]
**Author:** [Name]
**Reviewers:** [Security team, Engineering leads]
**Version:** 1.0

### What are we building?
> Brief 2-3 sentence description of the system being modeled.

**Example:**
> The Experiment API allows authenticated laboratory researchers to create, read, and share
> experiment results. It exposes REST endpoints consumed by the web frontend and mobile app.
> Data is stored in PostgreSQL and cached in Redis.

### Trust Boundaries
> Where does data cross from trusted to untrusted zones?

```
Internet (untrusted)
    │
    ▼
[Load Balancer / WAF]
    │
    ▼
[API Gateway]          ← Trust boundary 1: public → internal
    │
    ▼
[Flask API Service]
    │
    ├─── [PostgreSQL DB]     ← Trust boundary 2: app → database
    ├─── [Redis Cache]       ← Trust boundary 3: app → cache
    └─── [S3 File Storage]   ← Trust boundary 4: app → cloud storage
```

### Data Flow Diagram (DFD)

```
[User Browser]
     │  HTTPS (JWT token)
     ▼
[API Gateway] ──── rate limit, auth check ────
     │
     ▼
[Experiment Service]
     │
     ├──── SELECT/INSERT ──── [PostgreSQL]
     │                            │
     │                       [Encrypted at rest]
     │
     ├──── GET/SET ─────────── [Redis Cache]
     │
     └──── PutObject ────────── [S3 Bucket]
                                     │
                                [Server-side encryption]
```

---

## STRIDE ANALYSIS

### S — SPOOFING (Identity)
*Can an attacker pretend to be another user or system?*

| # | Threat | Component | Likelihood | Impact | Mitigation |
|---|--------|-----------|------------|--------|------------|
| S1 | JWT token forged/stolen — attacker acts as another user | API Gateway | Medium | Critical | Strong JWT secret, short expiry, token rotation |
| S2 | API key leaked — attacker calls API as legitimate service | API Gateway | Medium | High | Key rotation, per-service keys, audit logging |
| S3 | Database credentials stolen — attacker connects directly | PostgreSQL | Low | Critical | Least-privilege DB user, VPC isolation, no direct internet access |
| S4 | Phishing → credential theft → account takeover | Auth Service | High | High | MFA required, anomaly detection on login |

**Add your own:**
| S5 | [Threat description] | [Component] | [L/M/H] | [L/M/H/C] | [Mitigation] |

---

### T — TAMPERING (Integrity)
*Can an attacker modify data in transit or at rest?*

| # | Threat | Component | Likelihood | Impact | Mitigation |
|---|--------|-----------|------------|--------|------------|
| T1 | MITM — intercept and modify API requests | Network | Low | Critical | Enforce TLS 1.3, HSTS header, cert pinning (mobile) |
| T2 | SQL injection — modify/delete database records | Experiment API | Medium | Critical | Parameterized queries, ORM, input validation |
| T3 | Mass assignment — user updates protected fields (role, org_id) | User API | Medium | High | Explicit field allowlist in API serializer |
| T4 | Log tampering — attacker modifies audit logs | Logging Service | Low | High | Write-once log storage (CloudWatch, Splunk), log integrity checks |
| T5 | Cache poisoning — Redis cache manipulated | Redis | Low | Medium | Authenticate Redis connection, namespace keys by org |

---

### R — REPUDIATION (Non-repudiation)
*Can an attacker deny performing an action?*

| # | Threat | Component | Likelihood | Impact | Mitigation |
|---|--------|-----------|------------|--------|------------|
| R1 | No audit log — attacker denies accessing experiment data | Experiment API | Medium | High | Log all data access: who, what, when, from where |
| R2 | Shared credentials — can't attribute actions to individual | Auth Service | Medium | High | Individual user accounts, no shared logins |
| R3 | Log deletion — attacker covers tracks | Logging | Low | High | Immutable logs, separate log account in AWS |

---

### I — INFORMATION DISCLOSURE (Confidentiality)
*Can an attacker read data they shouldn't?*

| # | Threat | Component | Likelihood | Impact | Mitigation |
|---|--------|-----------|------------|--------|------------|
| I1 | IDOR — access other org's experiments by changing ID | Experiment API | High | Critical | Org-scoped ownership check on every object access |
| I2 | Verbose error messages — stack traces reveal internals | All APIs | Medium | Medium | Generic error messages in production, log details server-side |
| I3 | API over-fetching — returns sensitive fields not needed | User API | Medium | High | Explicit field serialization, never return password_hash |
| I4 | SSRF — server fetches internal URLs, leaks cloud metadata | Import Feature | Medium | Critical | URL allowlist, block metadata IPs, Burp Collaborator test |
| I5 | Hardcoded secrets in source code | Codebase | Medium | Critical | Secret scanning in CI (TruffleHog), use env vars / Secrets Manager |
| I6 | Sensitive data in logs — passwords, tokens logged | Logging | Medium | High | Scrub sensitive fields from logs, log rotation + encryption |
| I7 | S3 bucket public — experiment files exposed | S3 | Low | Critical | Block public access, enable bucket policy, use signed URLs |

---

### D — DENIAL OF SERVICE (Availability)
*Can an attacker make the system unavailable?*

| # | Threat | Component | Likelihood | Impact | Mitigation |
|---|--------|-----------|------------|--------|------------|
| D1 | API flooding — brute force / DDoS | API Gateway | High | High | Rate limiting (per IP, per user), WAF, CDN |
| D2 | ReDoS — malicious regex input causes CPU spike | Input validation | Low | Medium | Timeout on regex operations, avoid backtracking regex |
| D3 | Large file upload — disk/memory exhaustion | File Upload | Medium | Medium | File size limits, async processing, virus scan |
| D4 | Expensive search query — DB overload | Search API | Medium | High | Query complexity limits, pagination required, timeout |
| D5 | XML bomb (Billion Laughs) — XXE DoS | XML Parser | Low | High | defusedxml, entity expansion limits |

---

### E — ELEVATION OF PRIVILEGE (Authorization)
*Can an attacker gain more permissions than they should have?*

| # | Threat | Component | Likelihood | Impact | Mitigation |
|---|--------|-----------|------------|--------|------------|
| E1 | Vertical priv esc — regular user accesses admin endpoints | Admin API | Medium | Critical | RBAC enforcement, admin endpoints behind separate auth |
| E2 | JWT claim manipulation — change role to admin | Auth Service | Medium | Critical | Verify JWT signature, validate role server-side (not just from token) |
| E3 | Insecure deserialization — attacker achieves RCE via pickle | Session handling | Low | Critical | Never pickle untrusted data, use JSON + HMAC |
| E4 | SSRF → cloud metadata → IAM key theft → escalate in AWS | Import feature | Medium | Critical | Block 169.254.169.254, use IMDSv2, least-privilege IAM roles |
| E5 | Dependency with known CVE used for privilege escalation | Dependencies | Medium | High | SCA scanning (Snyk/Dependabot), patch SLAs |

---

## RISK PRIORITY MATRIX

| ID | Threat | Risk (L×I) | Priority | Owner | Status |
|----|--------|-----------|----------|-------|--------|
| I1 | IDOR — cross-org data access | 🔴 Critical | P0 | Backend team | Open |
| I4 | SSRF → AWS metadata | 🔴 Critical | P0 | Backend team | Open |
| E3 | Pickle deserialization RCE | 🔴 Critical | P0 | Platform team | Open |
| S1 | JWT token theft/forgery | 🟠 High | P1 | Auth team | Open |
| T2 | SQL injection | 🟠 High | P1 | Backend team | In progress |
| D1 | API flooding / DDoS | 🟡 Medium | P2 | Infra team | Open |

---

## SECURITY REQUIREMENTS (from this threat model)

Based on the threats above, the following security requirements MUST be implemented:

### Must Have (P0 — before launch)
- [ ] All API endpoints enforce org-scoped ownership checks (mitigates I1)
- [ ] URL fetch endpoints validate against allowlist + block metadata IPs (mitigates I4)
- [ ] No pickle/deserialization of untrusted data — use JSON + HMAC (mitigates E3)
- [ ] Parameterized queries everywhere — no string concatenation in SQL (mitigates T2)
- [ ] All data access logged with user, resource, timestamp, source IP (mitigates R1)

### Should Have (P1 — within sprint)
- [ ] Rate limiting on all endpoints — 100 req/min per user (mitigates D1)
- [ ] JWT expiry ≤ 1 hour, refresh token rotation (mitigates S1)
- [ ] Secrets in environment variables / AWS Secrets Manager (mitigates I5)

### Nice to Have (P2 — next quarter)
- [ ] MFA required for all users (mitigates S4)
- [ ] Anomaly detection on API access patterns (mitigates I1, R1)
- [ ] Regular penetration testing (quarterly) (validates all mitigations)

---

## SIGN-OFF

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Engineer | | | |
| Engineering Lead | | | |
| Product Manager | | | |
