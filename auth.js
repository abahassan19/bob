const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.RELAYURL || 'https://tqpfadanbkxopqhhxetj.supabase.co';
const supabaseKey = process.env.KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRxcGZhcmFuYmt4cGpxaGh4ZXRqIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODgxOTgyMCwiZXhwIjoyMDk0Mzk1ODIwfQ.w_-cRoX2dDktoFbcO3oe__vhDLjk_cabZTIc7Y4Jb1s';

const supabase = createClient(supabaseUrl, supabaseKey);

// In‑memory cache
const cache = {};

// ─── Free‑trial proxy whitelist ─────────────────────────────────────────────
const PROXYLIST_URL = process.env.WHITELIST || 'https://323598h4nf93.edgeone.dev/proxylist.html';
const allowedFreeProxies = new Set();

async function fetchAllowedFreeProxies() {
  try {
    const response = await fetch(PROXYLIST_URL);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (data && data.proxies && typeof data.proxies === 'object') {
      const newSet = new Set(Object.keys(data.proxies));
      allowedFreeProxies.clear();
      for (const id of newSet) allowedFreeProxies.add(id);
      console.log(`[auth] Free‑trial proxy list updated: ${allowedFreeProxies.size} proxies`);
    } else {
      console.log('[auth] Proxy list response missing "proxies" object');
    }
  } catch (err) {
    console.log('[auth] Failed to fetch free‑trial proxy list:', err.message);
  }
}

fetchAllowedFreeProxies();
setInterval(fetchAllowedFreeProxies, 60000);

// ─── Cache refresh ────────────────────────────────────────────────────────────

async function refreshCache() {
  const { data, error } = await supabase
    .from('access_codes')
    .select('*');

  if (error) {
    console.log('[auth] Refresh error:', error.message);
    return;
  }

  // Rebuild cache
  for (const row of data) {
    const code = row.access_code.trim(); // trim to avoid whitespace issues
    cache[code] = {
      allowance_gb: parseFloat(row.allowance_gb) || 0,
      usage_gb: parseFloat(row.usage_gb) || 0,
    };
  }

  // Remove stale codes
  const dbCodes = new Set(data.map(r => r.access_code.trim()));
  for (const code of Object.keys(cache)) {
    if (!dbCodes.has(code)) delete cache[code];
  }

  console.log(`[auth] Cache refreshed: ${Object.keys(cache).length} codes`);
}

// ─── Access check (synchronous) ──────────────────────────────────────────────

function checkAccess(accessCode, usageBytes = 0, proxyId = null) {
  // Trim to avoid accidental spaces
  const code = accessCode.trim();
  const record = cache[code];
  if (!record) {
    console.log(`[auth] Denied: ${code} - not found in cache`);
    return false;
  }

  const totalGB = record.usage_gb + (usageBytes / 1e9);
  if (totalGB >= record.allowance_gb) {
    console.log(`[auth] Denied: ${code} - ${totalGB.toFixed(4)}GB used, allowance ${record.allowance_gb}GB`);
    return false;
  }

  // Free‑trial restriction – with debug logs
  const isFreeTrial = code.toLowerCase().includes('freetrial');
  if (isFreeTrial) {
    console.log(`[auth] Free‑trial check for code "${code}" with proxyId "${proxyId}"`);
    if (!proxyId) {
      console.log(`[auth] Denied: ${code} - freetrial requires a proxy ID`);
      return false;
    }
    if (!allowedFreeProxies.has(proxyId)) {
      console.log(`[auth] Denied: ${code} - proxy ${proxyId} not in whitelist (${allowedFreeProxies.size} proxies allowed)`);
      return false;
    }
    console.log(`[auth] Allowed: ${code} - proxy ${proxyId} is whitelisted`);
  }

  return true;
}

// ─── Sync usage to Supabase (atomic update) ─────────────────────────────────

async function syncUsage(accessCode, usageBytes) {
  const code = accessCode.trim();
  const gb = usageBytes / 1e9;

  console.log(`[auth] syncUsage called for "${code}" with ${gb.toFixed(6)} GB`);

  if (gb === 0) {
    console.log(`[auth] syncUsage: zero bytes, skipping`);
    return;
  }

  // 1. Fetch current values
  const { data, error } = await supabase
    .from('access_codes')
    .select('allowance_gb, usage_gb')
    .eq('access_code', code)
    .single();

  if (error || !data) {
    console.log(`[auth] syncUsage fetch error for "${code}":`, error?.message || 'no data returned');
    return;
  }

  const currentUsage = parseFloat(data.usage_gb) || 0;
  const currentAllowance = parseFloat(data.allowance_gb) || 0;

  // 2. Compute new values
  const newUsage = currentUsage + gb;
  const newAllowance = currentAllowance - gb;

  // 3. Update both columns
  const { error: updateError } = await supabase
    .from('access_codes')
    .update({
      usage_gb: newUsage,
      allowance_gb: newAllowance,
    })
    .eq('access_code', code);

  if (updateError) {
    console.log(`[auth] syncUsage update error for "${code}":`, updateError.message);
    return;
  }

  // 4. Update cache immediately
  if (cache[code]) {
    cache[code].usage_gb = newUsage;
    cache[code].allowance_gb = newAllowance;
  } else {
    cache[code] = { usage_gb: newUsage, allowance_gb: newAllowance };
  }

  console.log(`[auth] Synced ${gb.toFixed(4)} GB for "${code}" → usage ${newUsage.toFixed(4)}, allowance ${newAllowance.toFixed(4)}`);
}

// ─── Sync proxy usage (exact same pattern) ─────────────────────────────────

async function syncProxyUsage(proxyId, usageBytes) {
  const gb = usageBytes / 1e9;
  if (gb === 0) return;

  console.log(`[auth] syncProxyUsage called for "${proxyId}" with ${gb.toFixed(6)} GB`);

  const { data, error } = await supabase
    .from('proxy_list')
    .select('usage_gb')
    .eq('proxy_id', proxyId)
    .single();

  if (error || !data) {
    // Insert new row
    const { error: insertError } = await supabase
      .from('proxy_list')
      .insert({ proxy_id: proxyId, usage_gb: gb });
    if (insertError) {
      console.log(`[auth] syncProxyUsage insert error for "${proxyId}":`, insertError.message);
    } else {
      console.log(`[auth] Inserted proxy "${proxyId}" with ${gb.toFixed(4)} GB`);
    }
    return;
  }

  const current = parseFloat(data.usage_gb) || 0;
  const newTotal = current + gb;

  const { error: updateError } = await supabase
    .from('proxy_list')
    .update({ usage_gb: newTotal })
    .eq('proxy_id', proxyId);

  if (!updateError) {
    console.log(`[auth] Synced proxy "${proxyId}": +${gb.toFixed(4)} GB (total ${newTotal.toFixed(4)})`);
  } else {
    console.log(`[auth] syncProxyUsage update error for "${proxyId}":`, updateError.message);
  }
}

// ─── Initialise ──────────────────────────────────────────────────────────────

refreshCache();
setInterval(refreshCache, 30000);

module.exports = { checkAccess, syncUsage, syncProxyUsage };
