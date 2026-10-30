import test from 'node:test';
import assert from 'node:assert/strict';
import { CandidateSecurityService } from '../src/security/tokenSigner.js';

test('CandidateSecurityService: generates tamper-proof signed URLs and rejects alterations', () => {
  const candidateId = 'cmtykw6c0000004igfwa7a18q';
  const signed = CandidateSecurityService.signCandidateAccess(candidateId, 24);

  assert.ok(signed.url.includes(candidateId));
  assert.ok(signed.url.includes('sig='));
  assert.ok(signed.url.includes('exp='));
  assert.ok(signed.signature.length === 64, 'HMAC-SHA256 hex signature should be 64 characters');

  // 1. Verify valid signature
  const validCheck = CandidateSecurityService.verifyCandidateAccess(
    candidateId,
    signed.expiresAt,
    signed.signature
  );
  assert.equal(validCheck.valid, true);

  // 2. Reject tampered signature
  const tamperedSig = signed.signature.slice(0, -4) + 'ffff';
  const tamperedCheck = CandidateSecurityService.verifyCandidateAccess(
    candidateId,
    signed.expiresAt,
    tamperedSig
  );
  assert.equal(tamperedCheck.valid, false);

  // 3. Reject altered candidate ID (IDOR prevention)
  const attackerId = 'cmtykw6c0000004igfwa9999z';
  const idorCheck = CandidateSecurityService.verifyCandidateAccess(
    attackerId,
    signed.expiresAt,
    signed.signature
  );
  assert.equal(idorCheck.valid, false);

  // 4. Reject expired link
  const expiredTimestamp = Math.floor(Date.now() / 1000) - 3600; // 1 hour in the past
  const expiredCheck = CandidateSecurityService.verifyCandidateAccess(
    candidateId,
    expiredTimestamp,
    signed.signature
  );
  assert.equal(expiredCheck.valid, false);
  assert.match(expiredCheck.reason, /expired/i);
});
