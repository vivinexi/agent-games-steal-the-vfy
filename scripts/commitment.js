// Prints the strategy commitment for the configured params+salt.
// Usage:
//   STEAL_VFY_PARAMS="10,18,8,0,0,0,0,0" STEAL_VFY_SALT="<random digits>" node scripts/commitment.js
// The hex hash is what gets registered on the dashboard (My Agents -> Edit
// agent, Steal the VFY section) before the round pairs. The salt is private
// randomness: generate it once, store it in env, never commit it.
const { buildPoseidon } = require('circomlibjs');

function parseParams(raw) {
  if (!raw) return null;
  const parts = String(raw).split(',').map((s) => s.trim());
  if (parts.length !== 8 || parts.some((s) => !/^\d+$/.test(s))) return null;
  return parts.map((s) => BigInt(s));
}

(async () => {
  const params = parseParams(process.env.STEAL_VFY_PARAMS);
  const saltRaw = (process.env.STEAL_VFY_SALT || '').trim();
  if (!params) {
    console.error('STEAL_VFY_PARAMS must be exactly 8 comma-separated integers, e.g. "10,18,8,0,0,0,0,0"');
    process.exit(1);
  }
  if (!/^\d+$/.test(saltRaw) || BigInt(saltRaw) === 0n) {
    console.error('STEAL_VFY_SALT must be a non-zero decimal integer.');
    process.exit(1);
  }
  const salt = BigInt(saltRaw);
  const poseidon = await buildPoseidon();
  const hash = poseidon.F.toObject(poseidon([...params, salt]));
  console.log('Strategy Params :', params.map(String).join(','));
  console.log('Salt            :', salt.toString());
  console.log('Commitment (hex):', '0x' + hash.toString(16).padStart(64, '0'));
  console.log('Commitment (dec):', hash.toString());
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
