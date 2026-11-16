// Local smoke tests for the Steal the VFY agent — spawns the real server as
// a child process with TEST secrets/params (never the dashboard secret) and
// checks the full HTTP behaviour. Usage: node test/local-test.js
// Note: each turn does a real Groth16 proof, which is slow on a small VM;
// the suite takes a few minutes. That latency is itself measured (see below).
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const path = require('node:path');
const snarkjs = require('snarkjs');
const { keccak256 } = require('js-sha3');

const PORT = 3457;
const SECRET = 'test-only-local-secret-0002';
const BASE = `http://127.0.0.1:${PORT}`;
const VK = require(path.join(__dirname, '..', 'circuits', 'verification_key.json'));
const MATCH = '9f4e1b2a-1111-2222-3333-444455556666';

function sampleTurn(overrides = {}, turn = 3) {
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId: MATCH,
    turn,
    issuedAt: new Date(Date.now() - 1000).toISOString(),
    deadlineAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    state: { selfBalance: '100', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: '0x0' }, // envelope hash is ignored for proofing; local commitment is used (see agent.js)
    resolverVersion: 'v1',
    nonce: 'test-nonce-' + turn,
    ...overrides,
  };
}

function sign(body) {
  const raw = JSON.stringify(body);
  return { raw, sig: crypto.createHmac('sha256', SECRET).update(raw).digest('hex') };
}
async function post(pathname, body, sigOverride) {
  const { raw, sig } = body === null ? { raw: '', sig: '' } : sign(body);
  const headers = { 'content-type': 'application/json' };
  if (sigOverride !== null) headers['x-agent-games-signature'] = sigOverride === undefined ? sig : sigOverride;
  const t0 = Date.now();
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body: raw || undefined, signal: AbortSignal.timeout(300000) });
  const text = await res.text();
  return { status: res.status, ms: Date.now() - t0, text, headers: res.headers, json: safeJson(text) };
}
function safeJson(t) { try { return JSON.parse(t); } catch { return null; } }
function verifyResponseSig(text, sig) {
  return !!sig && crypto.timingSafeEqual(
    Buffer.from(sig), Buffer.from(crypto.createHmac('sha256', SECRET).update(text).digest('hex')));
}

(async () => {
  const child = spawn('node', ['agent.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, AGENT_NAME: 'ozawa',
      STEAL_VFY_PARAMS: '10,18,8,0,0,0,0,0', STEAL_VFY_SALT: '98765432109876543210',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '', err = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { err += d; });
  let pass = 0, fail = 0;
  const check = (name, cond, extra = '') => {
    console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
    cond ? pass++ : fail++;
  };
  try {
    let up = false;
    for (let i = 0; i < 100 && !up; i++) {
      try { const r = await fetch(BASE + '/health', { signal: AbortSignal.timeout(2000) }); up = r.ok; } catch { await new Promise((r) => setTimeout(r, 300)); }
    }
    check('server starts and answers /health', up);
    const health = await (await fetch(BASE + '/health', { signal: AbortSignal.timeout(5000) })).json();
    check('GET /health returns status ok + hmac_configured + commitment',
      health.status === 'ok' && health.hmac_configured === true
      && typeof health.strategyCommitment === 'string' && health.strategyCommitment.startsWith('0x'),
      JSON.stringify(health));
    const root = await fetch(BASE + '/', { signal: AbortSignal.timeout(5000) });
    check('GET / returns 200 (no root 404)', root.ok);

    // 401s
    const noSig = await post('/agent', sampleTurn(), null);
    check('POST /agent without HMAC -> 401', noSig.status === 401, `got ${noSig.status}`);
    const badSig = await post('/agent', sampleTurn(), 'deadbeef');
    check('POST /agent with wrong HMAC -> 401', badSig.status === 401, `got ${badSig.status}`);

    // preflight
    const pre = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
    check('signed preflight -> {ok:true, protocolVersion:v1}', pre.status === 200 && pre.json && pre.json.ok === true && pre.json.protocolVersion === 'v1', pre.text.slice(0, 120));
    check('preflight response is HMAC-signed', verifyResponseSig(pre.text, pre.headers.get('x-agent-games-signature')));

    // valid EXTRACT turn -> 200 with verifying policy proof
    const ext = await post('/agent', sampleTurn());
    check('signed valid turn -> 200', ext.status === 200, `${ext.status} ${ext.text.slice(0, 120)}`);
    check('EXTRACT turn answered within 5 min deadline', ext.ms < 300000, `${ext.ms}ms (platform waits ~30s per push — see README)`);
    check('turn echoes matchId and turn', ext.json && ext.json.matchId === MATCH && ext.json.turn === 3);
    check('EXTRACT action carries amount == params[0] (10)', ext.json && ext.json.action && ext.json.action.type === 'EXTRACT' && ext.json.action.amount === 10, JSON.stringify(ext.json && ext.json.action));
    check('policyProof has circuitVersion v1 + proof + 9 public_signals',
      ext.json && ext.json.policyProof && ext.json.policyProof.circuitVersion === 'v1'
      && ext.json.policyProof.proof && Array.isArray(ext.json.policyProof.public_signals)
      && ext.json.policyProof.public_signals.length === 9,
      `public_signals=${ext.json && ext.json.policyProof && ext.json.policyProof.public_signals && ext.json.policyProof.public_signals.length}`);
    let proofOk = false;
    if (ext.json && ext.json.policyProof && ext.json.policyProof.proof) {
      proofOk = await snarkjs.groth16.verify(VK, ext.json.policyProof.public_signals, ext.json.policyProof.proof);
    }
    check('EXTRACT policy proof verifies against official vk', proofOk);
    const ps = ext.json && ext.json.policyProof && ext.json.policyProof.public_signals;
    check('public_signals order [commitment, matchId, turn, self, opp, action, amount, version]',
      !!ps && BigInt(health.strategyCommitment).toString() === ps[1]
      && ps[2] === BigInt('0x9f4e1b2a111122223333444455556666').toString()
      && ps[3] === '3' && ps[4] === '100' && ps[5] === '100' && ps[6] === '2' && ps[7] === '10' && ps[8] === '1',
      JSON.stringify(ps));
    check('publicInputsHash present and 0x-prefixed 32-byte hex',
      ext.json && ext.json.policyProof && /^0x[0-9a-f]{64}$/.test(ext.json.policyProof.publicInputsHash || ''),
      ext.json && ext.json.policyProof && ext.json.policyProof.publicInputsHash);
    // Independent recomputation of the documented publicInputsHash formula
    // (keccak256 over ABI-packed 32-byte big-endian fields) from the raw
    // turn inputs — not by calling the agent's helper — so a mismatch
    // between the agent's hash and the documented formula is caught.
    let hashMatches = false;
    if (ext.json && ext.json.policyProof) {
      const fields = [BigInt(ps[1]), BigInt('0x9f4e1b2a111122223333444455556666'), 3n, 100n, 100n, 2n, 10n, 1n];
      const packed = Buffer.concat(fields.map((f) => {
        const buf = Buffer.alloc(32);
        Buffer.from(f.toString(16).padStart(64, '0'), 'hex').copy(buf);
        return buf;
      }));
      hashMatches = ext.json.policyProof.publicInputsHash === '0x' + keccak256(packed);
    }
    check('publicInputsHash matches the documented keccak formula (independent recomputation)',
      hashMatches, ext.json && ext.json.policyProof && ext.json.policyProof.publicInputsHash);
    check('turn response is HMAC-signed', verifyResponseSig(ext.text, ext.headers.get('x-agent-games-signature')));
    check('idempotencyKey is a UUID', ext.json && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(ext.json.idempotencyKey || ''), ext.json && ext.json.idempotencyKey);
    check('proof and public_signals sit INSIDE policyProof (not top level)',
      ext.json && !('proof' in ext.json) && !('public_signals' in ext.json));

    // retry identical (same turn, fresh nonce) -> byte-identical response
    const retry = await post('/agent', sampleTurn({}, 3));
    check('retry of same (matchId, turn) returns byte-identical response', retry.text === ext.text);

    // FORTIFY state (self < 18) -> FORTIFY, no amount, verifying proof
    const fort = await post('/agent', sampleTurn({ state: { selfBalance: '10', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null } }, 4));
    check('low selfBalance -> FORTIFY', fort.json && fort.json.action && fort.json.action.type === 'FORTIFY', fort.text.slice(0, 120));
    check('FORTIFY response carries NO action.amount', fort.json && fort.json.action && !('amount' in fort.json.action));
    let fortOk = false;
    if (fort.json && fort.json.policyProof && fort.json.policyProof.proof) {
      fortOk = await snarkjs.groth16.verify(VK, fort.json.policyProof.public_signals, fort.json.policyProof.proof);
    }
    check('FORTIFY policy proof verifies', fortOk);
    check('FORTIFY idempotencyKey differs from EXTRACT turn key',
      fort.json && fort.json.idempotencyKey !== ext.json.idempotencyKey);

    // HOLD state (opponent <= 8) -> HOLD, no amount, verifying proof
    const hold = await post('/agent', sampleTurn({ state: { selfBalance: '100', opponentBalance: '5', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null } }, 5));
    check('low opponentBalance -> HOLD', hold.json && hold.json.action && hold.json.action.type === 'HOLD', hold.text.slice(0, 120));
    check('HOLD response carries NO action.amount', hold.json && hold.json.action && !('amount' in hold.json.action));
    let holdOk = false;
    if (hold.json && hold.json.policyProof && hold.json.policyProof.proof) {
      holdOk = await snarkjs.groth16.verify(VK, hold.json.policyProof.public_signals, hold.json.policyProof.proof);
    }
    check('HOLD policy proof verifies', holdOk);

    // malformed body (signed but not a turn) -> 4xx error, NOT a turn response
    const bad = await post('/agent', { hello: 'world' });
    check('signed non-turn body -> 4xx, not a turn response', bad.status >= 400 && bad.status < 500 && !(bad.json && bad.json.action), `got ${bad.status}`);
    check('malformed-body error response is HMAC-signed', verifyResponseSig(bad.text, bad.headers.get('x-agent-games-signature')));

    // expired deadline -> 410
    const exp = await post('/agent', sampleTurn({ deadlineAt: new Date(Date.now() - 60000).toISOString() }, 6));
    check('expired deadlineAt -> 410', exp.status === 410, `got ${exp.status}`);

    // wrong eventId -> 400
    const wrongEvent = await post('/agent', sampleTurn({ eventId: 'proof-gatekeeper' }, 7));
    check('wrong eventId -> 400', wrongEvent.status === 400, `got ${wrongEvent.status}`);

    console.log(`\nlocal-test: ${pass} passed, ${fail} failed`);
    if (err.trim()) console.log('--- server stderr ---\n' + err.trim().slice(0, 800));
    globalThis.__failures = fail;
  } finally {
    child.kill('SIGTERM');
  }
  process.exit(globalThis.__failures ? 1 : 0);
})().catch((e) => { console.error('TEST CRASH:', e); process.exit(2); });
