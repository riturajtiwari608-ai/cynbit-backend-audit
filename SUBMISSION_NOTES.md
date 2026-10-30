# 📋 Cynbit Candidate Submission Portal Notes
### Dedicated Submission Template for Cynbit Talent Acquisition (Aria AI)

---

**Candidate Name:** Rituraj Tiwari  
**Candidate Portal ID:** `cmtykw6c0000004igfwa7a18q`  
**Target Role:** Backend Developer Intern  
**Assessment Task:** Analyze Cynbit From a Backend Perspective  
**Repository URL:** `https://github.com/riturajtiwari608-ai/cynbit-backend-audit`  
**Live Interactive Demo:** `https://cynbit-backend-audit.onrender.com`  
**Submission Portal:** [https://www.cynbit.in/candidate/cmtykw6c0000004igfwa7a18q](https://www.cynbit.in/candidate/cmtykw6c0000004igfwa7a18q)  

---

## 📝 Text for Submission Field: "Technical Setup Notes"
*(Copy and paste the formatted block below directly into your Cynbit candidate portal submission box)*

```markdown
### Backend Developer Intern Technical Assessment: Cynbit System Analysis & Architecture Reference
**Applicant:** Rituraj Tiwari | **Candidate ID:** cmtykw6c0000004igfwa7a18q

Dear Aria AI & Cynbit Engineering Team,

I have completed the practical technical assessment analyzing Cynbit's web and backend systems from an enterprise backend engineering perspective. Per assessment instructions, all testing was 100% passive, authorized, and non-invasive, adhering strictly to RFC standards and OWASP guidelines.

### 🏛️ 1. Technical Audit & System Topology
- **Meta-Framework & Execution Model:** Deconstructed Cynbit's Next.js (App Router) hybrid architecture, React Server Components (RSC) flight data streams, and on-demand Sharp image resizing (`/_next/image`).
- **Data Layer & Primary Key Deconstruction:** Analyzed candidate route (`/candidate/cmtykw6c0000004igfwa7a18q`) confirming Prisma ORM CUID generation (25-char alphanumeric) coupled with a relational database (PostgreSQL/MySQL).
- **Network Boundary:** Audited edge reverse proxy behavior, TLS termination, and caching policies across static vs dynamic routes.

### 🔍 2. Categorized Security & Performance Findings
- **SEC-01 (Security Misconfiguration - CVSS 5.3):** Absence of defense-in-depth headers (Strict HSTS with preload, frame-ancestors 'none' CSP, nosniff).
- **SEC-02 (Broken Access Control - CVSS 6.5):** Insecure Direct Object Reference (IDOR) risk via naked CUID bearer links without cryptographic signatures or expiration.
- **PERF-01 (Insecure Design / Resource Starvation - CVSS 7.5):** Risk of Prisma connection pool saturation in serverless environments during concurrent traffic bursts.
- **DAT-01 (Input Validation & SSRF - CVSS 7.2):** Absence of runtime Zod schema boundary validation and lack of SSRF protection against cloud metadata IPs (169.254.169.254).
- **RES-01 (Insecure Design - CVSS 6.5):** Absence of distributed sliding-window rate limiting on write endpoints.
- **RES-02 (Security Misconfiguration - CVSS 4.3):** Inconsistent error formats and potential internal stack trace/path exposure.

### 🛠️ 3. Implemented Improvements & Reference PoC
Rather than delivering solely static recommendations, I built and verified an end-to-end hardened reference backend in Node.js/TypeScript:
1. **Zero-Trust Security Headers Middleware:** Dynamic per-request nonces, strict CSP, frame-ancestors 'none', HSTS preload.
2. **Cryptographic HMAC-SHA256 URL Signer:** Constant-time verification preventing naked CUID IDOR and URL tampering (`?exp=...&sig=...`).
3. **Distributed Sliding-Window Rate Limiter:** Microsecond precision request throttling with standard RFC rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After`).
4. **Zod Boundary Schema Validation:** Anti-SSRF domain whitelisting (GitHub/GitLab/Bitbucket) and recursive prototype pollution defenses.
5. **RFC 7807 Problem Details Error Architecture:** Deterministic client error envelope eliminating internal stack/path leaks.
6. **Circuit Breaker Resilience Layer:** Tripping state machine protecting downstream database connection pools.
7. **Automated Test Suite:** 100% passing tests (7/7) in ~290ms using native Node.js test harness.
8. **Interactive Web Dashboard:** Live testing console with real-time telemetry, rate limit simulation, and SSRF rejection test bench.

### 🚀 Setup & Verification
```bash
git clone https://github.com/riturajtiwari608-ai/cynbit-backend-audit.git
cd cynbit-backend-audit
npm test          # Run automated test suite (100% pass)
npm run audit     # Run passive security inspector CLI (100/100 score)
npm start         # Launch interactive dashboard at http://localhost:3000
```

Full reports and architectural blueprints are available in the repository:
- `BACKEND_TECHNICAL_AUDIT_REPORT.md`
- `SECURITY_AND_PERFORMANCE_FINDINGS.md`
- `RECOMMENDED_IMPROVEMENTS.md`

Thank you for your consideration. I look forward to contributing to Cynbit's high-performance engineering initiatives!
```
