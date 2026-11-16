# ozawa-duel — Steal the VFY duel agent · zkVerify Agent Games Season 01

Participant: **@sadesgos** (X verified, referral `F84XXTPX`) · Agent name: **ozawa-duel**
Track: **Steal the VFY** · Hosting: **Railway** (separate service from the Proof Gatekeeper agent)
Event: 13–17 Nov 2026, 7 Swiss rounds → Top 16 knockout · 20 turns/match · 100 VFY each

## Status (16 Nov 2026)

- ✅ Agent implemented: `agent.js` (Node.js, built-ins + snarkjs 0.7.6 + js-sha3 only).
- ✅ Groth16 policy proofs generate and verify against the official vfyPolicy key.
- ✅ Local tests green: circuit probe **46/46**, HTTP smoke tests **31/31**
  (`npm test` exit 0, ~18 s). See "Test results".
- ✅ Deployed 16 Nov 2026 ~18:44 WIB: Railway project "superb-strength",
  service agent-games-steal-the-vfy, https://agent-games-steal-the-vfy-production-8fb1ddee.up.railway.app
- ✅ Registered 16 Nov 2026 ~18:50 WIB: agent ozawa-duel, Steal the VFY only,
  HMAC secret set, strategy commitment ACTIVE REGISTERED, preflight OK (258ms),
  entered the arena.
- ⚠️ Practice turns FAILED 16 Nov 2026 ~19:00 WIB (3× Extract/Hold): "Agent
  response did not match the VFY protocol schema" — the agent produced valid
  Groth16 proofs, so the fault is a response field, not the proof. First fix
  (commit 31e4910, removed `agentTimestamp`) was WRONG and did not help.
  The platform diagnostic (practice, 21:42 WIB, pasted by the user) proved
  two things: (1) `agentTimestamp` IS a required string field in the Steal
  turn-response schema ("expected string, received undefined" when absent);
  (2) that dispatch went to the WRONG agent — the gatekeeper endpoint
  (agent-games-ozawa-production…), whose INVALID_TASK reply has none of the
  Steal fields, because the wrong agent was picked on the Practice page.
  Fix: `agentTimestamp` (ISO string, once per turn, cached) restored to the
  response; always dispatch practice for ozawa-duel. Re-testing practice
  after redeploy.
- ❌ The Proof Gatekeeper agent (`../agent-games-proof-gatekeeper`) is a SEPARATE
  service and is LIVE in Round 04 right now — do not touch it or its Railway
  service for this track. This folder deploys as its own Railway service.

## Protocol — verified from the official docs (16 Nov 2026)

Sources: https://agentgames.zkverify.io/build (section 06 Tournament protocol),
/events/steal-the-vfy, /rules, /api/circuit-info (read as text + raw HTML).

- **Endpoint: `POST /agent`** — register the FULL handler path (e.g.
  `https://<host>/agent`). The platform posts to the URL exactly as registered.
- **Turn envelope:** `{ protocolVersion: "v1", eventId: "steal-the-vfy", mode,
  matchId, turn, issuedAt, deadlineAt, state: { selfBalance, opponentBalance,
  selfFortifiedUntilTurn, opponentFortifiedUntilTurn }, strategyCommitment:
  { hash }, resolverVersion: "v1", nonce }`.
- **Response:** `{ matchId, turn, action: { type, amount? }, policyProof,
  agentTimestamp, idempotencyKey }` — echo matchId and turn exactly.
  `policyProof: { circuitVersion: "v1", proof, public_signals,
  proofReference?, publicInputsHash? }`. **proof and public_signals MUST sit
  INSIDE policyProof**, not at the top level (the #1 cause of lost turns:
  -2, resolved as HOLD).
- **Actions:** HOLD (free, no transfer), FORTIFY (cost 2, blocks up to 6 of
  incoming extraction this turn), EXTRACT N (free, steals up to N, max 10,
  from the opponent's exposed balance; a fortified opponent reduces the
  effective gain by 6). `action.amount` is REQUIRED for EXTRACT and must be
  **omitted entirely** for HOLD/FORTIFY (the schema rejects it even as 0).
- **publicInputsHash** (optional audit pointer): keccak256 of ABI-packed
  32-byte big-endian fields: commitment, matchId (dashes removed, as hex),
  turn, selfBalance, opponentBalance, action (HOLD=0, FORTIFY=1, EXTRACT=2),
  amount (0 for HOLD/FORTIFY), 1 (circuitVersion "v1" → 1). The platform
  independently computes this hash from the game state it knows.
- **Preflight** (`agent-games.preflight.v1`, signed): respond
  `{ ok: true, protocolVersion: "v1" }`, signed. Must pass before Active.
- **HMAC:** verify `x-agent-games-signature` over the RAW request body BEFORE
  parsing; sign every response over the raw response body. Secret ONLY from env
  `AGENT_GAMES_HMAC_SECRET` (dashboard → Rotate Secret, shown once).
- **Deadlines:** 5 min/turn; the platform waits ~30 s per push. Missing a turn
  = forced HOLD and -1; an invalid policy proof = -2 per turn. A match runs
  all 20 turns automatically. **A proof-less turn response (-2) is worse
  than a missed turn (-1)** — so this agent answers a signed 4xx/5xx error
  instead of a turn response when it cannot produce a valid proof.
- **idempotencyKey:** unique per turn, stable across retries. This agent
  derives it deterministically from (matchId, turn), formatted as a UUID,
  and caches the response per (matchId, turn) so a platform retry replays
  the byte-identical response.
- **Scoring:** win +18 / draw +9 / loss +3; verified-turn reliability bonus
  +0…+2; timeout -1/turn; invalid policy proof -2/turn. Prizes 100,000
  VFY/track (50k/30k/20k). Registration closes 21 Nov 2026 22:00 UTC.
- **Entry requirements:** signed preflight, practice turn, registered
  strategy commitment (Dashboard → My Agents → Edit agent, Steal section),
  one agent per owner in this event. Register mid-tournament to join from
  the next Swiss round, until the final round is paired.

## Circuit — verified locally against the official files

Files in `circuits/` (downloaded from agentgames.zkverify.io/circuits/):
`vfy-policy.wasm` (2,991,212 bytes, SHA-256 `bc099825…134d2`),
`vfy-policy_final.zkey` (810,586 bytes, SHA-256 `f9666a16…ce41`),
`verification_key.json` (exported with snarkjs; groth16/bn128, **nPublic = 9**).
vkHash from /api/circuit-info: `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`.
(Note: the task brief transcribed this hash 2 characters short; the
/api/circuit-info value above is authoritative and matches the build page.)

- 17 input signals. Public (8): `commitment, matchId, turnNumber,
  selfBalance, opponentBalance, action, amount, circuitVersion`. Private (9):
  `strategyParams[0..7]` (array of 8), `salt`.
- 9 public signals, output-then-public order:
  `[<output>, commitment, matchId, turnNumber, selfBalance, opponentBalance,
  action, amount, circuitVersion]`.
  The output (public[0]) binds the proof to the match and turn ONLY: it
  changes when matchId or turnNumber changes and not when balances,
  action, amount, params, or salt change (verified in the probe suite —
  the same public[0] appears for different params+salt on the same
  match+turn). Its exact preimage is not published (Poseidon(match, turn)
  in either order does not match) and the agent never needs to compute it
  (snarkjs returns it).
- `commitment = Poseidon(strategyParams[0..7], salt)`, verified with
  circomlibjs. The circuit asserts (line 72) that the Poseidon hash of the
  private params+salt equals the public `commitment` input — a wrong
  commitment refuses the witness.
- The circuit enforces ONE policy template over the private params
  (26-case prove/refuse matrix + boundaries, see test/probe-circuit.js):
  `selfBalance < params[1]` → FORTIFY; `opponentBalance <= params[2]` →
  HOLD; otherwise, `params[3] == 0` → EXTRACT `params[0]` (amount must
  equal params[0]); otherwise, `params[3] == 1` → HOLD (defensive mode:
  never extract). Boundaries: self == params[1] does NOT fortify (strict
  <); opponent == params[2] DOES hold (<=). Any other (state, action) pair
  refuses the witness (wrong action line 140, wrong EXTRACT amount line
  149, non-zero amount for HOLD/FORTIFY line 153, invalid action code
  line 140). `params[3]` is a boolean mode flag (line 98 rejects values
  other than 0/1); `params[4..7]` must be exactly 0 (reserved — lines
  75, 76, 77, 78 each assert one of them is 0).
- matchId encoding: UUID dashes removed, hex → BigInt. Fallback for
  non-hex ids: SHA-256(matchId) mod p. Action codes: HOLD=0, FORTIFY=1,
  EXTRACT=2. circuitVersion input = 1.
- **How the input names were found:** the official pages publish no input
  signal names and no input JSON schema — the wasm stores names only as
  FNV-1a 64-bit hashes. The names above were recovered by probing the
  compiled circuit itself (a candidate name either increments the
  "N out of 17 inputs set" counter or errors), then confirmed by a
  prove/verify matrix against the official wasm/zkey. The
  `strategyParams[0..7]` + `salt` shape was corroborated by a participant's
  public write-up; the semantics below were verified against the circuit,
  not taken on trust.

## Strategy — the committed policy

The circuit only lets one policy shape through (see above), so the strategy
IS the choice of the 8 private parameters. This agent commits:

```
params = [10, 18, 8, 0, 0, 0, 0, 0]
```

- **params[0] = 10 — EXTRACT the maximum whenever the position allows it.**
  EXTRACT is free, and a larger amount strictly increases the take under
  every documented resolver rule: the take is capped by the opponent's
  exposed balance, and a fortified opponent reduces the gain by a flat 6
  (10−6=4 beats 8−6=2). There is no documented downside to the maximum.
- **params[1] = 18 — FORTIFY when selfBalance < 18.** Below 18, one
  unblocked 10-extraction removes over half the stack and can zero it.
  Paying 2 to block up to 6 of it protects the stack and denies the
  opponent the gain. Above 18 the stack absorbs an extraction and the free
  EXTRACT is worth more than the protection.
- **params[2] = 8 — HOLD when opponentBalance <= 8.** Below 8 the
  opponent's exposed balance is nearly exhausted: extraction nets at most
  7, and ~0 against a fortifying opponent (they will fortify, since their
  own balance is below any sane threshold, paying 2 per fortify). Holding
  concedes nothing and lets their stack bleed 2 per fortify while mine is
  untouched. Above 8, extract.
- **params[3] = 0 — standard mode (extract when healthy).** `params[3]`
  is a boolean mode flag: 0 = extract, 1 = defensive mode (hold when
  healthy, never extract — the FORTIFY/HOLD branches are unchanged).
  Defensive mode was probed and works, but this agent ships 0: EXTRACT
  is free and the maximum take is strictly better whenever the position
  allows it.
- **params[4..7] = 0 — reserved, must be exactly 0.** The circuit asserts
  each of them is 0 (lines 75–78); a value of 1 already refuses the
  witness. They are shipped as 0.

The policy is deterministic (same game state → same action) and frozen by
the commitment hash at pairing time. The salt is private randomness bound
into the commitment; it is generated once at setup, stored in env
(`STEAL_VFY_SALT`), and never committed. Changing params or salt changes
the commitment hash, which must be re-registered on the dashboard before
the next pairing — mid-match changes are impossible by design.

**What the policy deliberately does NOT do:** the turn envelope also
carries `selfFortifiedUntilTurn` / `opponentFortifiedUntilTurn`, but the
circuit takes no fortification input — the committed policy is a function
of balances only. The agent logs those fields but cannot condition on
them, because any action the circuit cannot prove is a -2 turn. A
fortification-aware policy would need a different circuit version, which
does not exist for this season.

## Files

| File | What it is |
|---|---|
| `agent.js` | The agent. `POST /agent`, `GET /health`, `GET /`. |
| `circuits/` | Official `vfy-policy.wasm`, `vfy-policy_final.zkey`, `verification_key.json`. |
| `test/probe-circuit.js` | Circuit verification (46 checks). `npm run probe`. |
| `test/local-test.js` | HTTP smoke tests vs the real server (31 checks). `npm run smoke`. |
| `package.json` | `snarkjs@0.7.6`, `js-sha3` (keccak256) deps; `start: node agent.js`; `test` runs both suites. |
| `railway.json` | Nixpacks build, `startCommand: node agent.js`, healthcheck `/health`. |
| `.env.example` | Blank env template. `.env` is gitignored; never commit a real secret. |
| `scripts/commitment.js` | Prints the strategy commitment (hex + decimal) for given params+salt. |

## Test results (local, 16 Nov 2026)

`npm test` — **exit 0 in ~18 s** (foreground; backgrounded runs are far
slower because this VM starves backgrounded shells of CPU — see item 1 in
"Still unverified").

- **Circuit probe (46/46):** input-name discovery (turnNumber, not turn),
  valid EXTRACT proof verifies with 9 public signals in the documented
  order, public[0] changes with matchId/turn only (not with
  balances/action/params/salt), 25-case policy matrix with boundaries
  (self == 18 extracts, opp == 8 holds, wrong amounts/actions refused at
  the exact circuit lines 72/98/140/149/153), params[3] mode flag (0 =
  extract, 1 = defensive; 2/99 refused at line 98), params[4..7] must be
  exactly 0 (lines 75–78), publicInputsHash deterministic and
  field-sensitive. Single-proof time 484–1159 ms.
- **HTTP smoke (31/31):** /health + / 200, unsigned/wrong-HMAC → 401,
  signed preflight → signed `{ok:true, protocolVersion:"v1"}`, signed
  valid EXTRACT turn → 200 in 1448 ms with a verifying policy proof,
  correct 9-signal order, publicInputsHash matching the documented
  keccak formula by independent recomputation, signed response, UUID
  idempotencyKey, proof/public_signals inside policyProof only,
  byte-identical retry, FORTIFY and HOLD turns (no action.amount,
  verifying proofs, distinct idempotencyKeys), malformed body → 400
  (signed, no turn response), expired deadline → 410, wrong eventId → 400.

## Deploy to Railway (exact steps — needs the user's Railway account)

**Do this as a SEPARATE Railway service — never in the Proof Gatekeeper
service (project pacific-flow, service agent-games-ozawa), which is live.**

1. **Generate the strategy secret material ONCE** (locally, never in chat):
   `node scripts/commitment.js` with `STEAL_VFY_PARAMS="10,18,8,0,0,0,0,0"`
   and a fresh random `STEAL_VFY_SALT` (e.g. 20 random digits). It prints the
   commitment hash — that is what gets registered on the dashboard.
2. **Push this folder to a public personal GitHub repo** (dashboard requires a
   public repo on a personal account; org repos are not supported). Suggested
   name: `agent-games-steal-the-vfy` (or reuse the participant's repo pattern).
3. **Railway:** new project (or a new service in a new project) → Deploy from
   GitHub repo → select the repo. Railway detects Node.js (Nixpacks) and runs
   `npm install` then `node agent.js` (see `railway.json`). The `PORT` env is
   set by Railway.
4. **Set variables** in Railway (Variables tab):
   - `AGENT_GAMES_HMAC_SECRET` = the value from the dashboard **Rotate
     Secret** (see next step — set the dashboard value here; do NOT invent one).
   - `AGENT_NAME` = `ozawa-duel`.
   - `STEAL_VFY_PARAMS` = `10,18,8,0,0,0,0,0`
   - `STEAL_VFY_SALT` = the salt from step 1 (never in chat, never in git).
5. **Generate a public domain** in Railway (Settings → Networking → Generate
   Domain). The endpoint to register is `https://<railway-domain>/agent`.
6. **Check health:** `curl https://<railway-domain>/health` → `{"status":"ok",...}`
   and confirm `strategyCommitment` equals the hash from step 1.

## Register on the dashboard (needs the user — no credentials here)

1. Dashboard → My agents → **Register agent**: Agent Name (TBD — the
   dashboard allows 1 agent per automated event and max 3 per participant;
   the Proof Gatekeeper agent is already named `ozawa`, so pick a name here —
   e.g. `ozawa-duel` — unless the dashboard accepts reusing `ozawa`),
   tick **Steal the VFY**, Repository URL = the public GitHub repo URL from
   step 2, Agent Endpoint = `https://<railway-domain>/agent`. Submit.
2. On the new agent card: **Rotate Secret** → copy the one-time plaintext →
   paste it as `AGENT_GAMES_HMAC_SECRET` in Railway Variables → **redeploy /
   restart** the Railway service.
3. Dashboard → My Agents → Edit agent → **Steal the VFY section: register the
   strategy commitment** — paste the commitment hash from step 1 (the same
   hash `GET /health` reports). This MUST be done before Swiss Round 1 pairs
   (the platform cannot pair an agent without an active commitment), and the
   commitment is frozen when matches are paired.
4. Dashboard → run **Preflight** (must pass; reply is
   `{ok:true, protocolVersion:"v1"}` signed). If it fails with
   "endpoint must return signed protocol-v1 JSON", the HMAC secret on Railway
   does not match the dashboard value.
5. Dashboard → **Practice** → run practice turns (categories
   "Steal the VFY — Fortify/Extract/Hold"; capped at 10 dispatches per
   active agent per hour). Practice is the only way to settle the open
   questions in "Still unverified" — especially real proof latency and the
   fortify duration.
6. Events → Steal the VFY → **Enter the arena**. Register mid-tournament to
   join from the next Swiss round, until the final round is paired. Keep the
   Railway service running during rounds; a stopped service forfeits turns.

## Still unverified — do NOT claim these are settled

1. **Proof latency on a hosted CPU — locally fast, but measure on Railway.**
   In the foreground on this VM one vfyPolicy proof takes ~0.6–1.9 s
   (single-proof timing in the probe suite; the HTTP smoke suite's
   EXTRACT turn answered in well under 5 s). That is far inside the
   platform's ~30 s per push. Caveat: backgrounded shell sessions on this
   VM get almost no CPU (an earlier 12-proof probe took ~8 min wall time
   with only ~5 s of CPU), so a backgrounded timing measurement looks
   20–60× slower than the real proof time — the foreground numbers above
   are the honest ones. The first practice turn on Railway is still the
   real test, since Railway's CPU class differs from this VM.
2. **Fortify duration.** The docs say FORTIFY "blocks up to 6 VFY of
   incoming extraction this turn", but the envelope carries
   `selfFortifiedUntilTurn` / `opponentFortifiedUntilTurn` — turn numbers
   that suggest the protection may last past one resolution. If it lasts
   multiple turns, fortifying is worth more than this strategy assumes and
   params[1] could go higher. Observe the fields across practice turns.
3. **Exact resolver arithmetic.** The event page's resolution table is
   qualitative (caps, the -6 reduction, the 2 cost). Edge cases — balances
   floored at 0, whether a fortified agent's own extraction is affected,
   what happens when both extract against small exposed balances — are
   only observable in a live match replay.
4. **public[0] preimage.** The circuit's output public signal binds the
   proof to the match and turn only (not to the strategy or salt — proven
   by identical public[0] across different params+salt), but its exact
   hash preimage was not identified from the published docs
   (Poseidon(match, turn) in either order does not match). It does not
   matter operationally: the agent never computes it, snarkjs returns it,
   and the platform verifies the proof.
5. **Strategy-commitment registration UX.** The dashboard's Steal section
   (Edit agent) is where the commitment hash goes, but the exact field
   (paste a hash? pick a circuit version?) was not observed — only the
   build page's description. Confirm in the dashboard before pairing.
6. **Preflight transport detail.** As with the gatekeeper agent: the
   preflight request is documented as a signed POST to "your endpoint";
   `GET /health` and `GET /` both return 200 as a safety net.

## Run locally

```bash
npm install
STEAL_VFY_PARAMS="10,18,8,0,0,0,0,0" STEAL_VFY_SALT="<20 random digits>" \
  AGENT_GAMES_HMAC_SECRET=<test-only-secret> node agent.js   # :3000
npm test   # probe + smoke
node scripts/commitment.js   # prints the commitment hash to register
```
