// Probe script — verifies the vfyPolicy circuit's 17 inputs against the
// OFFICIAL circuit files (circuits/vfy-policy.wasm + vfy-policy_final.zkey).
// This is a local test only: no network, no deployment, no dashboard.
// Usage: node test/probe-circuit.js
//
// What the official pages do NOT publish (and this probe establishes):
// the input signal names, the public-signals order, and the exact policy
// the circuit enforces. The names were recovered by probing the compiled
// circuit (a candidate name either increments the "N out of 17 inputs set"
// counter or errors with "Too many values"), then confirmed by the matrix
// below. See README "Circuit" for the full story.
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');
const { keccak256 } = require('js-sha3');
const path = require('node:path');

const WASM = path.join(__dirname, '..', 'circuits', 'vfy-policy.wasm');
const ZKEY = path.join(__dirname, '..', 'circuits', 'vfy-policy_final.zkey');
const VK = require(path.join(__dirname, '..', 'circuits', 'verification_key.json'));

// The committed strategy (same as the agent default): EXTRACT 10,
// FORTIFY when self < 18, HOLD when opponent <= 8, standard mode, reserved 0.
const PARAMS = [10n, 18n, 8n, 0n, 0n, 0n, 0n, 0n];
const SALT = 98765432109876543210n;
const MATCH = '9f4e1b2a-1111-2222-3333-444455556666';
const MATCH_DEC = BigInt('0x' + MATCH.replace(/-/g, '')).toString();

let poseidon;
async function commitmentFor(params, salt) {
  return poseidon.F.toString(poseidon([...params.map(BigInt), salt]));
}

function inputFor(overrides = {}, params = PARAMS, salt = SALT, commitment) {
  return {
    commitment: commitment ?? '',
    matchId: MATCH_DEC,
    turnNumber: '3',
    selfBalance: '100',
    opponentBalance: '100',
    action: '2',
    amount: '10',
    circuitVersion: '1',
    salt: salt.toString(),
    strategyParams: params.map(String),
    ...overrides,
  };
}

async function prove(input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    return { ok, publicSignals, ms: Date.now() - t0 };
  } catch (e) {
    return { err: (e.message || '').split('\n')[0], ms: Date.now() - t0 };
  }
}
const lineOf = (r) => {
  const m = /line: (\d+)/.exec(r.err || '');
  return m ? Number(m[1]) : null;
};

(async () => {
  poseidon = await buildPoseidon();
  const COMMITMENT = await commitmentFor(PARAMS, SALT);
  let pass = 0, fail = 0;
  const check = (name, cond, extra = '') => {
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
    cond ? pass++ : fail++;
  };
  const base = (over = {}, params, salt, commitment) =>
    inputFor(over, params, salt, commitment ?? COMMITMENT);

  // 0. Negative control: a wrong input name must fail (turn is not a signal;
  // the circuit takes turnNumber).
  try {
    const wrong = base(); delete wrong.turnNumber; wrong.turn = '3';
    await snarkjs.groth16.fullProve(wrong, WASM, ZKEY);
    check('wrong-name control (turn instead of turnNumber) fails', false);
  } catch (e) {
    check('wrong-name control (turn instead of turnNumber) fails', /not found|Too many values|turn/i.test(e.message), e.message.split('\n')[0]);
  }

  // 1. Valid EXTRACT proof verifies; 9 public signals in documented order.
  const valid = await prove(base());
  check('valid EXTRACT proof verifies', valid.ok, `${valid.ms}ms`);
  check('public signals count == 9', valid.publicSignals && valid.publicSignals.length === 9,
    `got ${valid.publicSignals && valid.publicSignals.length}`);
  const ps = valid.publicSignals || [];
  check('public[1] == commitment (Poseidon of params+salt)', ps[1] === COMMITMENT);
  check('public signals order [2..8] == matchId, turn, self, opp, action, amount, version',
    ps[2] === MATCH_DEC && ps[3] === '3' && ps[4] === '100' && ps[5] === '100'
    && ps[6] === '2' && ps[7] === '10' && ps[8] === '1', JSON.stringify(ps.slice(2)));
  check('single proof is fast (< 30 s push window)', valid.ms < 30000, `${valid.ms}ms`);

  // 2. public[0] binds the proof to (strategy, match, turn) — not to the move.
  const otherMatch = await prove(base({ matchId: BigInt('0xaaaaaaaa111122223333444455556666').toString() }));
  check('different matchId -> different public[0], same public[1..8] except matchId',
    otherMatch.ok && otherMatch.publicSignals[0] !== ps[0]
    && otherMatch.publicSignals.slice(1, 2).join() === ps.slice(1, 2).join()
    && otherMatch.publicSignals.slice(3).join() === ps.slice(3).join());
  const otherTurn = await prove(base({ turnNumber: '7' }));
  check('different turnNumber -> different public[0], same rest except turn',
    otherTurn.ok && otherTurn.publicSignals[0] !== ps[0]
    && otherTurn.publicSignals[3] === '7'
    && otherTurn.publicSignals.slice(4).join() === ps.slice(4).join());
  const fort = await prove(base({ selfBalance: '10', opponentBalance: '100', action: '1', amount: '0' }));
  check('same match/turn, different move -> SAME public[0] (binds match+turn, not the move)',
    fort.ok && fort.publicSignals[0] === ps[0]);

  // 3. Salt change changes the commitment (public[1]); the other public
  // signals stay the same. Whether public[0] also changes is logged, not
  // asserted (it binds strategy+match+turn; the exact preimage is unknown).
  const salt2 = 11111111111111111111n;
  const commit2 = await commitmentFor(PARAMS, salt2);
  const saltCase = await prove(base({}, PARAMS, salt2, commit2));
  check('different salt -> different commitment, same other signals',
    saltCase.ok && saltCase.publicSignals[1] === commit2
    && saltCase.publicSignals.slice(2).join() === ps.slice(2).join());
  console.log(`INFO  public[0] after salt change: ${saltCase.ok && saltCase.publicSignals[0] !== ps[0] ? 'changed' : 'unchanged'}`);

  // 4. Policy matrix — the circuit is the referee. Each wrong (state, action)
  // pair must refuse the witness; each right one must prove + verify.
  const cases = [
    // [name, overrides, expectProve, expectedLineOnRefusal]
    ['healthy EXTRACT 10 proves', {}, true, null],
    ['healthy EXTRACT 9 refused (amount != params[0])', { amount: '9' }, false, 149],
    ['healthy EXTRACT 11 refused (amount != params[0])', { amount: '11' }, false, 149],
    ['healthy EXTRACT 0 refused', { amount: '0' }, false, 149],
    ['healthy HOLD refused', { action: '0', amount: '0' }, false, 140],
    ['healthy FORTIFY refused', { action: '1', amount: '0' }, false, 140],
    ['healthy action=3 refused', { action: '3', amount: '0' }, false, 140],
    ['low self FORTIFY proves', { selfBalance: '10', action: '1', amount: '0' }, true, null],
    ['low self EXTRACT refused', { selfBalance: '10' }, false, 140],
    ['low self HOLD refused', { selfBalance: '10', action: '0', amount: '0' }, false, 140],
    ['low opp HOLD proves', { opponentBalance: '5', action: '0', amount: '0' }, true, null],
    ['low opp EXTRACT refused', { opponentBalance: '5' }, false, 140],
    ['low opp FORTIFY refused', { opponentBalance: '5', action: '1', amount: '0' }, false, 140],
    ['both low FORTIFY proves (self check first)', { selfBalance: '10', opponentBalance: '5', action: '1', amount: '0' }, true, null],
    ['both low HOLD refused', { selfBalance: '10', opponentBalance: '5', action: '0', amount: '0' }, false, 140],
    ['self == params[1] (18) EXTRACT proves (strict <)', { selfBalance: '18' }, true, null],
    ['self == params[1] (18) FORTIFY refused', { selfBalance: '18', action: '1', amount: '0' }, false, 140],
    ['self == 17 FORTIFY proves', { selfBalance: '17', action: '1', amount: '0' }, true, null],
    ['opp == params[2] (8) HOLD proves (<=)', { opponentBalance: '8', action: '0', amount: '0' }, true, null],
    ['opp == params[2] (8) EXTRACT refused', { opponentBalance: '8' }, false, 140],
    ['opp == 9 EXTRACT proves', { opponentBalance: '9' }, true, null],
    ['opp == 9 HOLD refused', { opponentBalance: '9', action: '0', amount: '0' }, false, 140],
    ['FORTIFY with amount=5 refused', { selfBalance: '10', action: '1', amount: '5' }, false, 153],
    ['HOLD with amount=5 refused', { opponentBalance: '5', action: '0', amount: '5' }, false, 153],
    ['wrong commitment refused', { commitment: '12345' }, false, 72],
  ];
  for (const [name, over, expectProve, line] of cases) {
    const r = await prove(base(over));
    if (expectProve) {
      check(name, r.ok === true, r.err || `${r.ms}ms`);
    } else {
      check(name, !r.ok && (line === null || lineOf(r) === line),
        r.ok ? 'proved unexpectedly' : `line ${lineOf(r)} (want ${line})`);
    }
  }

  // 5. params[3] is a mode flag (0 = extract, 1 = defensive/never extract).
  const p3 = (v) => { const a = [...PARAMS]; a[3] = BigInt(v); return a; };
  const defHold = await prove(base({ action: '0', amount: '0' }, p3(1), SALT, await commitmentFor(p3(1), SALT)));
  check('params[3]=1: healthy HOLD proves (defensive mode)', defHold.ok === true, defHold.err || '');
  const defExt = await prove(base({}, p3(1), SALT, await commitmentFor(p3(1), SALT)));
  check('params[3]=1: healthy EXTRACT refused', !defExt.ok && lineOf(defExt) === 140, `line ${lineOf(defExt)}`);
  const defFort = await prove(base({ selfBalance: '10', action: '1', amount: '0' }, p3(1), SALT, await commitmentFor(p3(1), SALT)));
  check('params[3]=1: low-self FORTIFY still proves', defFort.ok === true, defFort.err || '');
  for (const v of [2, 99]) {
    const r = await prove(base({}, p3(v), SALT, await commitmentFor(p3(v), SALT)));
    check(`params[3]=${v} refused (mode flag must be 0/1)`, !r.ok && lineOf(r) === 98, `line ${lineOf(r)}`);
  }

  // 6. params[4..7] must be exactly 0 (reserved).
  for (let i = 4; i <= 7; i++) {
    const a = [...PARAMS]; a[i] = 1n;
    const r = await prove(base({}, a, SALT, await commitmentFor(a, SALT)));
    check(`params[${i}]=1 refused (reserved, must be 0)`, !r.ok && lineOf(r) === 71 + i, `line ${lineOf(r)} (want ${71 + i})`);
  }

  // 7. publicInputsHash formula (keccak256, ABI-packed) — sanity: deterministic
  // and field-sensitive. The agent's implementation of the same formula is
  // checked against an independent computation in the HTTP smoke test.
  const hashFields = (commitment, matchId, turn, selfB, oppB, action, amount) => {
    const fields = [BigInt(commitment), BigInt(matchId), BigInt(turn), BigInt(selfB), BigInt(oppB), BigInt(action), BigInt(amount), 1n];
    const packed = Buffer.concat(fields.map((f) => {
      const buf = Buffer.alloc(32);
      Buffer.from(f.toString(16).padStart(64, '0'), 'hex').copy(buf);
      return buf;
    }));
    return '0x' + keccak256(packed);
  };
  const h1 = hashFields(COMMITMENT, MATCH_DEC, '3', '100', '100', '2', '10');
  const h2 = hashFields(COMMITMENT, MATCH_DEC, '3', '100', '100', '2', '10');
  const h3 = hashFields(COMMITMENT, MATCH_DEC, '4', '100', '100', '2', '10');
  check('publicInputsHash is deterministic and 0x-prefixed 32-byte hex',
    h1 === h2 && /^0x[0-9a-f]{64}$/.test(h1), h1);
  check('publicInputsHash changes when the turn changes', h1 !== h3);

  console.log(`\nprobe: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('PROBE CRASH:', e); process.exit(2); });
