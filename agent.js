// ozawa-duel — Steal the VFY duel agent for zkVerify Agent Games Season 01
// Participant: @sadesgos. Hosting: Railway (separate service from the Proof
// Gatekeeper agent — do NOT deploy this into the gatekeeper service).
// Local-only build: NOT deployed, NOT registered.
//
// Protocol source of truth (read 2026-11-16, text fetch + raw HTML):
//   https://agentgames.zkverify.io/build          (section 06 Tournament protocol)
//   https://agentgames.zkverify.io/events/steal-the-vfy
//   https://agentgames.zkverify.io/rules
//   https://agentgames.zkverify.io/api/circuit-info
//
// VERIFIED protocol facts (do not "improve" these from memory):
// - Endpoint: POST at the FULL handler path you register, e.g. /agent.
//   "The platform posts to the URL exactly as registered."
// - Incoming turn envelope:
//   { protocolVersion: "v1", eventId: "steal-the-vfy", mode, matchId,
//     turn, issuedAt, deadlineAt,
//     state: { selfBalance, opponentBalance, selfFortifiedUntilTurn,
//              opponentFortifiedUntilTurn },
//     strategyCommitment: { hash }, resolverVersion: "v1", nonce }
// - Response (200, application/json):
//   { matchId, turn, action: { type, amount? }, policyProof, agentTimestamp,
//     idempotencyKey }
//   action.type is HOLD / FORTIFY / EXTRACT. amount is REQUIRED for EXTRACT
//   and must be OMITTED ENTIRELY for HOLD and FORTIFY (even 0) — the schema
//   rejects the field otherwise.
// - policyProof: { circuitVersion: "v1", proof, public_signals,
//   proofReference?, publicInputsHash? }. proof and public_signals MUST sit
//   INSIDE policyProof, not at the top level — leaving them out is the #1
//   cause of lost turns (turn scored -2, resolved as HOLD).
// - publicInputsHash (optional audit pointer): keccak256 of ABI-packed
//   32-byte big-endian fields, in this order:
//     commitment, matchId (dashes removed, as hex), turn, selfBalance,
//     opponentBalance, action (HOLD=0, FORTIFY=1, EXTRACT=2), amount
//     (0 for HOLD/FORTIFY), 1 (circuitVersion "v1" -> 1).
//   The platform independently computes this hash from the game state it
//   knows and rejects proofs where the hashes diverge.
// - Preflight request: { type: "agent-games.preflight.v1", agent_id,
//   issued_at, nonce } -> respond { ok: true, protocolVersion: "v1" }, signed.
// - Every inbound request: verify HMAC x-agent-games-signature over the RAW
//   body BEFORE parsing. Every response: sign with the same header over the
//   raw response body. Secret comes ONLY from env AGENT_GAMES_HMAC_SECRET
//   (dashboard "Rotate Secret"). A placeholder/mismatched secret fails
//   preflight with a signature error.
// - Turn deadline: 5 minutes; the platform waits ~30 s per push. Missing a
//   turn = forced HOLD and -1; an invalid policy proof = -2 per turn. The
//   match runs all 20 turns automatically.
// - idempotencyKey: fresh per turn, stable across retries of the SAME turn
//   (only the first submission per key is accepted). This agent derives it
//   deterministically from (matchId, turn), so a platform retry replays the
//   byte-identical response instead of a second submission.
//
// Circuit facts — verified locally against the OFFICIAL circuit files
// (circuits/vfy-policy.wasm + vfy-policy_final.zkey; vk: groth16/bn128,
// nPublic = 9; see test/probe-circuit.js):
// - 17 input signals. Public inputs (8): commitment, matchId, turnNumber,
//   selfBalance, opponentBalance, action, amount, circuitVersion.
//   Private inputs (9): strategyParams[0..7] (array of 8), salt.
// - 9 public signals, output-then-public order:
//   [ <circuit output>, commitment, matchId, turnNumber, selfBalance,
//     opponentBalance, action, amount, circuitVersion ]
//   The output (public[0]) binds the proof to the committed strategy plus
//   the match and turn: it changes when matchId or turnNumber changes and
//   not when balances/action/amount change. Its exact preimage is not
//   published and the agent never needs to compute it (snarkjs returns it).
// - commitment = Poseidon(strategyParams[0..7], salt), verified with
//   circomlibjs. The circuit asserts (line 72) that the Poseidon hash of
//   the private params+salt equals the public `commitment` input — a wrong
//   commitment refuses the witness, so the params+salt in env MUST hash to
//   the commitment registered on the dashboard before pairing.
// - The circuit enforces ONE policy template over the private params
//   (verified by a 19-case prove/refuse matrix in test/probe-circuit.js):
//     selfBalance < params[1]        -> FORTIFY (amount 0)
//     opponentBalance <= params[2]   -> HOLD    (amount 0)   [<=, not <]
//     otherwise, params[3] == 0      -> EXTRACT params[0]    (amount == params[0])
//     otherwise, params[3] == 1      -> HOLD    (defensive mode: never extract)
//   Any other (state, action) pair refuses the witness: wrong action for
//   the state (line 140), EXTRACT amount != params[0] (line 149),
//   non-zero amount for HOLD/FORTIFY (line 153), invalid action code (140).
//   Boundaries: selfBalance == params[1] does NOT fortify (strict <);
//   opponentBalance == params[2] DOES hold (<=).
// - params[3] is a boolean mode flag (line 98 rejects values other than 0/1).
//   params[4..7] must be exactly 0 (reserved; lines 75-78 each assert one
//   of them is 0). The agent validates all of this at startup and refuses
//   to start on an unprovable configuration.
// - matchId encoding: UUID dashes removed, hex -> BigInt (fits the field).
//   Fallback for non-hex ids: SHA-256(matchId) mod p (deterministic).
// - action codes: HOLD=0, FORTIFY=1, EXTRACT=2. circuitVersion input = 1.
//
// STRATEGY (the committed policy — see README for the full reasoning):
//   params = [10, 18, 8, 0, 0, 0, 0, 0]
//   - EXTRACT 10 whenever the position allows it: EXTRACT is free, and a
//     larger amount strictly increases the take under every documented
//     resolver rule (cap = opponent's exposed balance; a fortified
//     opponent reduces the gain by a flat 6, not proportionally).
//   - FORTIFY when selfBalance < 18: below 18, one unblocked 10-extraction
//     removes over half the stack. Paying 2 to block up to 6 of it protects
//     the stack and denies the opponent.
//   - HOLD when opponentBalance <= 8: the opponent's exposed balance is
//     nearly exhausted (extraction nets at most 7, ~0 against a fortifying
//     opponent) while the opponent keeps paying 2 per fortify; holding
//     concedes nothing and lets their stack bleed.
//   - params[3] = 0: standard mode (extract when healthy). params[3] = 1
//     would be "defensive mode" (hold when healthy, never extract).
//   - params[4..7] = 0: reserved, must be exactly 0 (circuit lines 75-78).
//
// FAIL-CLOSED rules:
// - HMAC mismatch / missing secret -> 401, no body processed.
// - Malformed envelope (missing matchId/turn/state/balances, wrong eventId
//   or protocolVersion, expired deadlineAt) -> signed 4xx error, NOT a turn
//   response (a proof-less turn response costs -2; a failed delivery -1).
// - Proof generation failure (policy/circuit disagreement — a config error)
//   -> signed 500 error, NOT a proof-less turn response, for the same reason.
// - On any uncertainty the agent answers the policy action with a valid
//   proof; it never invents an action the circuit cannot prove.

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const snarkjs = require('snarkjs');
const { keccak256 } = require('js-sha3');

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const AGENT_NAME = process.env.AGENT_NAME || 'ozawa';
const CIRCUIT_DIR = process.env.CIRCUIT_DIR || path.join(__dirname, 'circuits');
const WASM_PATH = path.join(CIRCUIT_DIR, 'vfy-policy.wasm');
const ZKEY_PATH = path.join(CIRCUIT_DIR, 'vfy-policy_final.zkey');
const VK_PATH = path.join(CIRCUIT_DIR, 'verification_key.json');

// BN128 scalar field prime (for the matchId fallback hash).
const FIELD_P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

for (const f of [WASM_PATH, ZKEY_PATH, VK_PATH]) {
  if (!fs.existsSync(f)) {
    console.error(`FATAL: missing circuit file: ${f}`);
    console.error('Download from https://agentgames.zkverify.io/circuits/ into ./circuits/');
    process.exit(1);
  }
}
const VK = require(VK_PATH);
if (VK.nPublic !== 9) {
  console.error(`FATAL: unexpected verification key nPublic=${VK.nPublic} (expected 9)`);
  process.exit(1);
}
if (!HMAC_SECRET) {
  console.error('WARNING: AGENT_GAMES_HMAC_SECRET is not set — every request will be 401 and');
  console.error('preflight will fail. Set it from the dashboard (Rotate Secret) and restart.');
}

// ---- Strategy configuration (env only; the commitment freezes these) ----
function parseParams(raw) {
  if (!raw) return null;
  const parts = String(raw).split(',').map((s) => s.trim());
  if (parts.length !== 8) return null;
  if (parts.some((s) => !/^\d+$/.test(s))) return null;
  return parts.map((s) => BigInt(s));
}
const PARAMS = parseParams(process.env.STEAL_VFY_PARAMS);
const SALT = process.env.STEAL_VFY_SALT && /^\d+$/.test(process.env.STEAL_VFY_SALT.trim())
  ? BigInt(process.env.STEAL_VFY_SALT.trim())
  : null;
if (!PARAMS) {
  console.error('FATAL: STEAL_VFY_PARAMS must be exactly 8 comma-separated integers, e.g. "10,18,8,0,0,0,0,0".');
  console.error('The params define the committed strategy; without them no valid proof can be built.');
  process.exit(1);
}
if (PARAMS[0] < 1n || PARAMS[0] > 10n) {
  console.error(`FATAL: STEAL_VFY_PARAMS[0] (EXTRACT amount) must be 1..10, got ${PARAMS[0]}.`);
  process.exit(1);
}
if (PARAMS[3] !== 0n && PARAMS[3] !== 1n) {
  console.error(`FATAL: STEAL_VFY_PARAMS[3] (mode flag) must be 0 (extract) or 1 (defensive, never extract), got ${PARAMS[3]}.`);
  process.exit(1);
}
if (PARAMS.slice(4).some((p) => p !== 0n)) {
  console.error(`FATAL: STEAL_VFY_PARAMS[4..7] are reserved and must be exactly 0, got ${PARAMS.slice(4).map(String).join(',')}.`);
  process.exit(1);
}
if (SALT === null || SALT === 0n) {
  console.error('FATAL: STEAL_VFY_SALT must be a non-zero decimal integer (private randomness).');
  console.error('Generate one once (e.g. 20 random digits), store it in env, and register the');
  console.error('commitment it produces. A changing salt changes the commitment every restart.');
  process.exit(1);
}

const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

let poseidon = null;
let commitmentDecimal = null;
let commitmentHex = null;
async function initCommitment() {
  const { buildPoseidon } = require('circomlibjs');
  poseidon = await buildPoseidon();
  const hash = poseidon.F.toObject(poseidon([...PARAMS, SALT]));
  commitmentDecimal = hash.toString();
  commitmentHex = '0x' + hash.toString(16).padStart(64, '0');
  console.log(`strategy commitment: ${commitmentHex} (params ${PARAMS.map(String).join(',')})`);
  console.log('Register this hash on the dashboard (My Agents -> Edit agent, Steal the VFY section)');
  console.log('before the round pairs, or the platform will reject every turn.');
}

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}
function safeEqual(a, b) {
  const ba = Buffer.from(a || '', 'utf8');
  const bb = Buffer.from(b || '', 'utf8');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
function signResponse(res, status, bodyObj) {
  const raw = JSON.stringify(bodyObj);
  if (HMAC_SECRET) res.setHeader('x-agent-games-signature', hmacHex(HMAC_SECRET, raw));
  res.setHeader('content-type', 'application/json');
  res.writeHead(status);
  res.end(raw);
}

// Deterministic policy — MUST match the circuit-enforced template exactly:
//   self < params[1] -> FORTIFY; opponent <= params[2] -> HOLD;
//   healthy + params[3]==0 -> EXTRACT params[0]; healthy + params[3]==1 -> HOLD.
// The circuit refuses the witness for any other (state, action) pair, so the
// decision function and the circuit can never disagree if the params match.
function decideMove(selfBalance, opponentBalance) {
  const self = BigInt(selfBalance);
  const opp = BigInt(opponentBalance);
  if (self < PARAMS[1]) return { type: 'FORTIFY', amountNum: 0 };
  if (opp <= PARAMS[2]) return { type: 'HOLD', amountNum: 0 };
  if (PARAMS[3] === 1n) return { type: 'HOLD', amountNum: 0 }; // defensive mode
  return { type: 'EXTRACT', amountNum: Number(PARAMS[0]) };
}

// matchId: UUID dashes removed, hex -> BigInt. Fallback: SHA-256(matchId) mod p.
function encodeMatchId(matchId) {
  const hex = String(matchId || '').replace(/^0x/i, '').replace(/-/g, '');
  if (/^[0-9a-fA-F]+$/.test(hex)) return BigInt('0x' + hex).toString();
  const h = crypto.createHash('sha256').update(String(matchId || '')).digest('hex');
  return (BigInt('0x' + h) % FIELD_P).toString();
}

// keccak256 of 8 ABI-packed 32-byte big-endian fields (see header).
function publicInputsHash(commitment, matchId, turn, selfBalance, opponentBalance, action, amount) {
  const fields = [
    BigInt(commitment),
    BigInt(encodeMatchId(matchId)),
    BigInt(turn),
    BigInt(selfBalance),
    BigInt(opponentBalance),
    ACTION_CODE[action],
    BigInt(amount),
    1n, // circuitVersion "v1" -> 1
  ];
  const packed = Buffer.concat(fields.map((f) => {
    const buf = Buffer.alloc(32);
    Buffer.from(f.toString(16).padStart(64, '0'), 'hex').copy(buf);
    return buf;
  }));
  return '0x' + keccak256(packed);
}

// Deterministic idempotency key: unique per (matchId, turn), stable across
// retries of the same turn, formatted as a UUID.
function idempotencyKey(matchId, turn) {
  const hex = crypto.createHash('sha256').update(`${matchId}:${turn}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

const responseCache = new Map(); // "matchId:turn" -> serialized response (retry = identical)
const pendingProofs = new Map(); // "matchId:turn" -> in-flight proof promise

async function handleTurn(env) {
  const matchId = env.matchId;
  const turn = env.turn;
  const state = env.state || {};
  const cacheKey = `${matchId}:${turn}`;
  if (responseCache.has(cacheKey)) return responseCache.get(cacheKey);
  if (pendingProofs.has(cacheKey)) return pendingProofs.get(cacheKey);

  const job = (async () => {
    const selfBalance = String(state.selfBalance);
    const opponentBalance = String(state.opponentBalance);

    // Warn (but proceed with the local commitment) if the frozen hash the
    // platform sent does not match what these params+salt hash to. A mismatch
    // means the dashboard commitment was registered from different params or
    // salt and the platform will reject the turn — fix the registration.
    const frozen = env.strategyCommitment && env.strategyCommitment.hash;
    if (frozen && BigInt(frozen).toString() !== commitmentDecimal) {
      console.error(`MISMATCH: envelope strategyCommitment ${frozen} != local ${commitmentHex}.`);
      console.error('The registered commitment does not match these params+salt. Re-register it.');
    }

    const move = decideMove(selfBalance, opponentBalance);
    const circuitInput = {
      commitment: commitmentDecimal,
      matchId: encodeMatchId(matchId),
      turnNumber: String(turn),
      selfBalance,
      opponentBalance,
      action: ACTION_CODE[move.type].toString(),
      amount: String(move.amountNum),
      circuitVersion: '1',
      salt: SALT.toString(),
      strategyParams: PARAMS.map(String),
    };
    const t0 = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput, WASM_PATH, ZKEY_PATH);
    console.log(`proof ${matchId} turn ${turn} ${move.type}${move.type === 'EXTRACT' ? ' ' + move.amountNum : ''} in ${Date.now() - t0}ms`);

    const action = move.type === 'EXTRACT'
      ? { type: 'EXTRACT', amount: move.amountNum }
      : { type: move.type }; // amount omitted entirely for HOLD/FORTIFY
    const out = {
      matchId,
      turn,
      action,
      policyProof: {
        circuitVersion: 'v1',
        proof,
        public_signals: publicSignals,
        publicInputsHash: publicInputsHash(
          commitmentDecimal, matchId, turn, selfBalance, opponentBalance, move.type, move.amountNum),
      },
      // agentTimestamp is REQUIRED by the Steal turn-response schema:
      // the platform diagnostic (practice, 2026-11-16 21:42 WIB) lists
      // "agentTimestamp: Invalid input: expected string, received
      // undefined" when it is absent. It is generated once per turn and
      // cached with the rest of the response, so retries stay identical.
      // (The earlier removal, commit 31e4910, was based on a wrong guess
      // that the extra field caused the rejection; the diagnostic proved
      // the opposite. The same diagnostic also showed a practice dispatch
      // can land on the wrong agent — the gatekeeper endpoint — when the
      // wrong agent is picked on the Practice page, so always dispatch
      // for ozawa-duel.)
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idempotencyKey(matchId, turn),
    };
    const raw = JSON.stringify(out);
    responseCache.set(cacheKey, raw);
    return raw;
  })();
  pendingProofs.set(cacheKey, job);
  try {
    return await job;
  } finally {
    pendingProofs.delete(cacheKey);
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({
      status: 'ok', agent: AGENT_NAME, protocol: 'agent-games.steal-the-vfy.v1',
      hmac_configured: Boolean(HMAC_SECRET), circuit: 'vfy-policy/v1', nPublic: 9,
      strategyCommitment: commitmentHex,
    }));
  }
  if (req.method === 'GET' && (req.url === '/' || req.url === '')) {
    res.setHeader('content-type', 'application/json');
    return res.end(JSON.stringify({ agent: AGENT_NAME, track: 'steal-the-vfy', status: 'ok' }));
  }
  // Canonical handler path (per /build: POST /agent, full registered path).
  if (req.method !== 'POST' || req.url !== '/agent') {
    res.writeHead(404); return res.end('not found');
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    // 1. Verify HMAC over the RAW body, BEFORE parsing.
    const sig = req.headers['x-agent-games-signature'];
    if (!HMAC_SECRET || !sig || !safeEqual(sig, hmacHex(HMAC_SECRET, raw))) {
      res.writeHead(401); return res.end('unauthorized');
    }
    let body;
    try { body = JSON.parse(raw.toString('utf8')); }
    catch { return signResponse(res, 400, { error: 'invalid_json' }); }

    // 2. Preflight handshake (signed): { ok: true, protocolVersion: "v1" }.
    if (body && body.type === 'agent-games.preflight.v1') {
      console.log(`preflight nonce=${body.nonce || ''}`);
      return signResponse(res, 200, { ok: true, protocolVersion: 'v1' });
    }

    // 3. Turn envelope. Fail closed on bad shape: a signed 4xx error, NOT a
    // proof-less turn response (the platform scores a proof-less turn -2,
    // worse than a missed turn at -1).
    if (!body || typeof body !== 'object' || body.eventId !== 'steal-the-vfy'
      || body.matchId === undefined || body.turn === undefined
      || !body.state || body.state.selfBalance === undefined
      || body.state.selfBalance === null || body.state.selfBalance === ''
      || body.state.opponentBalance === undefined
      || body.state.opponentBalance === null || body.state.opponentBalance === '') {
      return signResponse(res, 400, { error: 'invalid_turn_envelope' });
    }
    if (body.protocolVersion !== undefined && body.protocolVersion !== 'v1') {
      return signResponse(res, 400, { error: 'unsupported_protocol_version' });
    }
    if (body.deadlineAt) {
      const deadline = Date.parse(body.deadlineAt);
      if (!Number.isNaN(deadline) && Date.now() > deadline) {
        return signResponse(res, 410, { error: 'expired_turn' });
      }
    }
    try {
      const outRaw = await handleTurn(body);
      if (HMAC_SECRET) res.setHeader('x-agent-games-signature', hmacHex(HMAC_SECRET, outRaw));
      res.setHeader('content-type', 'application/json');
      res.writeHead(200);
      return res.end(outRaw);
    } catch (e) {
      // Proof generation failed (policy/circuit disagreement = config error).
      // Never answer with a proof-less turn response (-2); a failed delivery
      // is scored as a miss (-1) and the platform may retry.
      console.error(`turn ${body.matchId}:${body.turn} proof failed: ${String(e && e.message).split('\n')[0]}`);
      return signResponse(res, 500, { error: 'proof_failed' });
    }
  });
});

initCommitment().then(() => {
  server.listen(PORT, () => console.log(
    `ozawa-duel steal-the-vfy listening on :${PORT} (agent=${AGENT_NAME}, hmac_configured=${Boolean(HMAC_SECRET)})`));
}).catch((e) => {
  console.error('FATAL: could not compute strategy commitment:', e && e.message);
  process.exit(1);
});

module.exports = { server, decideMove, encodeMatchId, publicInputsHash, idempotencyKey };
