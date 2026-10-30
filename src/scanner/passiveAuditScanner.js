/**
 * Passive HTTP Security & Architecture Audit Scanner
 * Analyzes observable headers, protocol versions, and latency
 * without performing any invasive probing, fuzzing, or attacks.
 */
export class PassiveAuditScanner {
  /**
   * Evaluates an HTTP headers dictionary against industry security standards.
   * 
   * @param {Record<string, string>} rawHeaders 
   * @param {number} [latencyMs=0]
   * @returns {{ score: number, grade: string, checks: Array<{ name: string, status: 'PASS'|'WARN'|'FAIL', weight: number, details: string }> }}
   */
  static auditHeaders(rawHeaders, latencyMs = 0) {
    // Normalize header keys to lowercase
    const headers = {};
    for (const [key, value] of Object.entries(rawHeaders)) {
      headers[key.toLowerCase()] = String(value);
    }

    const checks = [];
    let earnedPoints = 0;
    let totalPoints = 0;

    const addCheck = (name, passed, warn, weight, passMsg, failMsg) => {
      totalPoints += weight;
      if (passed) {
        earnedPoints += weight;
        checks.push({ name, status: 'PASS', weight, details: passMsg });
      } else if (warn) {
        earnedPoints += Math.floor(weight / 2);
        checks.push({ name, status: 'WARN', weight, details: failMsg });
      } else {
        checks.push({ name, status: 'FAIL', weight, details: failMsg });
      }
    };

    // 1. Strict-Transport-Security (HSTS)
    const hsts = headers['strict-transport-security'];
    if (hsts) {
      const hasPreload = /preload/i.test(hsts);
      const hasSub = /includesubdomains/i.test(hsts);
      const ageMatch = hsts.match(/max-age=(\d+)/i);
      const age = ageMatch ? parseInt(ageMatch[1], 10) : 0;

      if (age >= 31536000 && hasSub && hasPreload) {
        addCheck('Strict-Transport-Security (HSTS)', true, false, 20, 'Production Grade (>= 1yr, subdomains, preload)', '');
      } else if (age > 0) {
        addCheck('Strict-Transport-Security (HSTS)', false, true, 20, '', `Partial HSTS configured (age=${age}s, subdomains=${hasSub})`);
      } else {
        addCheck('Strict-Transport-Security (HSTS)', false, false, 20, '', 'HSTS header missing or misconfigured');
      }
    } else {
      addCheck('Strict-Transport-Security (HSTS)', false, false, 20, '', 'Missing HSTS header (Vulnerable to SSL stripping)');
    }

    // 2. Content-Security-Policy (CSP)
    const csp = headers['content-security-policy'];
    if (csp) {
      const hasFrameAncestors = /frame-ancestors/i.test(csp);
      const hasDefaultSrc = /default-src/i.test(csp);
      if (hasFrameAncestors && hasDefaultSrc) {
        addCheck('Content-Security-Policy (CSP)', true, false, 25, 'Strong CSP with frame-ancestors & default-src directives', '');
      } else {
        addCheck('Content-Security-Policy (CSP)', false, true, 25, '', 'Permissive or partial CSP detected');
      }
    } else {
      addCheck('Content-Security-Policy (CSP)', false, false, 25, '', 'Missing CSP (Vulnerable to XSS and clickjacking)');
    }

    // 3. X-Frame-Options
    const xfo = headers['x-frame-options'];
    if (xfo && (xfo.toUpperCase() === 'DENY' || xfo.toUpperCase() === 'SAMEORIGIN')) {
      addCheck('X-Frame-Options', true, false, 15, `Properly configured (${xfo})`, '');
    } else {
      addCheck('X-Frame-Options', false, false, 15, '', 'Missing X-Frame-Options header');
    }

    // 4. X-Content-Type-Options
    const xcto = headers['x-content-type-options'];
    if (xcto && xcto.toLowerCase() === 'nosniff') {
      addCheck('X-Content-Type-Options', true, false, 15, 'Properly set to nosniff', '');
    } else {
      addCheck('X-Content-Type-Options', false, false, 15, '', 'Missing nosniff (Vulnerable to MIME-sniffing)');
    }

    // 5. Referrer-Policy
    const refPolicy = headers['referrer-policy'];
    if (refPolicy) {
      addCheck('Referrer-Policy', true, false, 10, `Configured (${refPolicy})`, '');
    } else {
      addCheck('Referrer-Policy', false, true, 10, '', 'Default browser referrer policy fallback');
    }

    // 6. Permissions-Policy
    const permPolicy = headers['permissions-policy'];
    if (permPolicy) {
      addCheck('Permissions-Policy', true, false, 10, `Active (${permPolicy.slice(0, 35)}...)`, '');
    } else {
      addCheck('Permissions-Policy', false, true, 10, '', 'Missing Permissions-Policy');
    }

    // 7. Information Leakage (X-Powered-By)
    const poweredBy = headers['x-powered-by'];
    if (!poweredBy) {
      addCheck('Information Concealment', true, false, 5, 'Server technology header properly suppressed', '');
    } else {
      addCheck('Information Concealment', false, false, 5, '', `Leaked server tech: ${poweredBy}`);
    }

    const score = Math.round((earnedPoints / totalPoints) * 100);
    let grade = 'F';
    if (score >= 95) grade = 'A+';
    else if (score >= 85) grade = 'A';
    else if (score >= 75) grade = 'B';
    else if (score >= 60) grade = 'C';
    else if (score >= 45) grade = 'D';

    return {
      score,
      grade,
      latencyMs,
      checks
    };
  }

  /**
   * Passively inspects a live target URL using standard HTTP fetch.
   * 
   * @param {string} targetUrl 
   * @returns {Promise<{ url: string, score: number, grade: string, latencyMs: number, headers: Record<string, string>, checks: any[] }>}
   */
  static async scanUrl(targetUrl) {
    const start = Date.now();
    try {
      const response = await fetch(targetUrl, {
        method: 'HEAD',
        redirect: 'follow',
        headers: {
          'User-Agent': 'CynbitTechnicalAuditBot/1.0 (Passive Academic Evaluation; Candidate Rituraj Tiwari)'
        }
      });
      const latencyMs = Date.now() - start;

      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key] = value;
      });

      const audit = this.auditHeaders(headers, latencyMs);

      return {
        url: targetUrl,
        statusCode: response.status,
        ...audit,
        headers
      };
    } catch (err) {
      return {
        url: targetUrl,
        error: String(err instanceof Error ? err.message : err),
        score: 0,
        grade: 'N/A',
        latencyMs: Date.now() - start,
        checks: []
      };
    }
  }
}
