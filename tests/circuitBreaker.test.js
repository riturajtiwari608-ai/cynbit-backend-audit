import test from 'node:test';
import assert from 'node:assert/strict';
import { CircuitBreaker, CircuitState } from '../src/resilience/circuitBreaker.js';

test('CircuitBreaker: trips to OPEN after threshold and protects downstream resources', async () => {
  const breaker = new CircuitBreaker(2, 500); // 2 failures triggers open, 500ms cooldown

  let attempts = 0;
  const failingAction = async () => {
    attempts++;
    throw new Error('Database connection timed out');
  };

  // Attempt 1: Fails
  await assert.rejects(async () => {
    await breaker.execute(failingAction);
  }, /Database connection timed out/);
  assert.equal(breaker.getStatus().state, CircuitState.CLOSED);

  // Attempt 2: Fails -> Trips circuit breaker to OPEN
  await assert.rejects(async () => {
    await breaker.execute(failingAction);
  }, /Database connection timed out/);
  assert.equal(breaker.getStatus().state, CircuitState.OPEN);

  // Attempt 3: Immediate reject WITHOUT executing the underlying failing action
  await assert.rejects(async () => {
    await breaker.execute(failingAction);
  }, /Circuit breaker is OPEN/);
  assert.equal(attempts, 2, 'Underlying failing action should NOT have been invoked on attempt 3');
});
