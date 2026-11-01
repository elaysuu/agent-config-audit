'use strict';
const PRODUCT_ID = '7pBQNmGnG6Ej982eySWLjQ==';
async function verify(key, { fetchImpl = globalThis.fetch, productId = PRODUCT_ID } = {}) {
  if (!key) return { team: false, reason: 'no license key' };
  if (productId.startsWith('REPLACE_')) return { team: false, reason: 'product_id not configured in this build' };
  try {
    const r = await fetchImpl('https://api.gumroad.com/v2/licenses/verify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ product_id: productId, license_key: key, increment_uses_count: 'false' }).toString() });
    const j = await r.json(); if (!j.success) return { team: false, reason: 'license key not valid for this product' };
    const p = j.purchase || {};
    if (p.refunded || p.chargebacked || p.disputed) return { team: false, reason: 'purchase refunded/disputed' };
    for (const f of ['subscription_cancelled_at', 'subscription_ended_at', 'subscription_failed_at']) if (p[f]) return { team: false, reason: f };
    return { team: true, reason: 'ok' };
  } catch (e) { return { team: false, reason: `license server unreachable (${e.message})` }; }
}
module.exports = { verify, PRODUCT_ID };
