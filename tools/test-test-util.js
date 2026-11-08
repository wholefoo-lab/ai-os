// tools/test-test-util.js
// Direct unit test for makeRunner(), the micro-harness extracted out of seven tools/test-*.js suites
// (tools/test-util.js:109-126) to kill a 7-instance duplication-gate trip. The suites that USE
// makeRunner only exercise it indirectly through their own assertions; this proves the helper itself
// — including the one non-trivial bit, truncating a multi-line Error.message to its first line — and
// that two instances don't share state, the property the whole extraction relies on.
'use strict';
const assert = require('assert');
const { assert: ok, done, makeRunner } = require('./test-util');

console.log('test-util:makeRunner');

// Capture console.log output for the duration of fn(), restoring the real one even on throw.
const captureLog = (fn) => {
  const real = console.log;
  const lines = [];
  console.log = (...args) => lines.push(args.join(' '));
  try { fn(); } finally { console.log = real; }
  return lines;
};

// Stub process.exit for the duration of fn(), returning the code it was called with (or undefined).
const captureExit = (fn) => {
  const real = process.exit;
  let code;
  process.exit = (c) => { code = c; };
  try { fn(); } finally { process.exit = real; }
  return code;
};

const check = (label, fn) => {
  try { fn(); ok(true, label); }
  catch (e) { ok(false, label + ' — ' + e.message); }
};

check('a passing fn increments pass and logs nothing', () => {
  const { t } = makeRunner();
  const lines = captureLog(() => t('ok case', () => {}));
  assert.deepStrictEqual(lines, []);
});

check('a throwing fn is caught, not propagated, and logs one FAIL line', () => {
  const { t } = makeRunner();
  const lines = captureLog(() => t('bad case', () => { throw new Error('boom'); }));
  assert.deepStrictEqual(lines, ['  FAIL bad case\n        boom']);
});

check('a multi-line Error.message is truncated to its first line in the FAIL output', () => {
  const { t } = makeRunner();
  const lines = captureLog(() => t('multiline', () => { throw new Error('first line\nsecond line\nthird'); }));
  assert.deepStrictEqual(lines, ['  FAIL multiline\n        first line']);
});

check('finish() prints the pass/fail summary and exits 0 when nothing failed', () => {
  const { t, finish } = makeRunner();
  t('p1', () => {});
  t('p2', () => {});
  let lines, code;
  lines = captureLog(() => { code = captureExit(finish); });
  assert.deepStrictEqual(lines, ['  2 passed, 0 failed']);
  assert.strictEqual(code, 0);
});

check('finish() reports the right counts and exits 1 when something failed', () => {
  const { t, finish } = makeRunner();
  let code;
  const lines = captureLog(() => {
    t('p1', () => {});
    t('f1', () => { throw new Error('nope'); });
    t('p2', () => {});
    code = captureExit(finish);
  });
  assert.deepStrictEqual(lines, ['  FAIL f1\n        nope', '  2 passed, 1 failed']);
  assert.strictEqual(code, 1);
});

check('two makeRunner() instances do not share pass/fail state', () => {
  const a = makeRunner();
  const b = makeRunner();
  const lines = captureLog(() => {
    a.t('a-pass', () => {});
    b.t('b-fail', () => { throw new Error('isolated'); });
    captureExit(a.finish);
    captureExit(b.finish);
  });
  assert.deepStrictEqual(lines, ['  FAIL b-fail\n        isolated', '  1 passed, 0 failed', '  0 passed, 1 failed']);
});

done();
