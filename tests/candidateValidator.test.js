import test from 'node:test';
import assert from 'node:assert/strict';
import { validateCandidateSubmission } from '../src/validation/candidateValidator.js';

test('CandidateValidator: validates authentic submissions and halts malicious inputs', () => {
  const validPayload = {
    candidateId: 'cmtykw6c0000004igfwa7a18q',
    repositoryUrl: 'https://github.com/riturajtiwari608-ai/cynbit-backend-audit',
    technicalNotes: 'Comprehensive audit report and hardened architectural reference implementation with unit tests.'
  };

  // 1. Valid payload must pass
  const validResult = validateCandidateSubmission(validPayload);
  assert.equal(validResult.valid, true);
  assert.ok(validResult.data);
  assert.equal(validResult.data.candidateId, validPayload.candidateId);

  // 2. Reject malformed CUID
  const badIdResult = validateCandidateSubmission({
    ...validPayload,
    candidateId: 'invalid-id-1234'
  });
  assert.equal(badIdResult.valid, false);
  assert.ok(badIdResult.errors.some(e => e.field === 'candidateId'));

  // 3. Reject non-whitelisted VCS host
  const untrustedHostResult = validateCandidateSubmission({
    ...validPayload,
    repositoryUrl: 'https://untrusted-file-host.xyz/repo.zip'
  });
  assert.equal(untrustedHostResult.valid, false);
  assert.ok(untrustedHostResult.errors.some(e => e.field === 'repositoryUrl'));

  // 4. Reject SSRF to AWS EC2 metadata service
  const ssrfResult = validateCandidateSubmission({
    ...validPayload,
    repositoryUrl: 'http://169.254.169.254/latest/meta-data/'
  });
  assert.equal(ssrfResult.valid, false);
  assert.ok(ssrfResult.errors.some(e => e.message.includes('SSRF') || e.field === 'repositoryUrl'));

  // 5. Reject short technical notes
  const shortNotesResult = validateCandidateSubmission({
    ...validPayload,
    technicalNotes: 'Too short'
  });
  assert.equal(shortNotesResult.valid, false);
  assert.ok(shortNotesResult.errors.some(e => e.field === 'technicalNotes'));

  // 6. Reject Prototype Pollution payload
  const pollutionPayload = JSON.parse('{"__proto__": {"admin": true}, "candidateId": "cmtykw6c0000004igfwa7a18q", "repositoryUrl": "https://github.com/test/repo", "technicalNotes": "Testing prototype pollution payload..."}');
  const pollutionResult = validateCandidateSubmission(pollutionPayload);
  assert.equal(pollutionResult.valid, false);
  assert.ok(pollutionResult.errors.some(e => e.field === 'security'));
});
