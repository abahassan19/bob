const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.RELAYURL || 'https://tqpfadanbkxopqhhxetj.supabase.co';
const supabaseKey = process.env.KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRxcGZhcmFuYmt4cGpxaGh4ZXRqIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODgxOTgyMCwiZXhwIjoyMDk0Mzk1ODIwfQ.w_-cRoX2dDktoFbcO3oe__vhDLjk_cabZTIc7Y4Jb1s';

const supabase = createClient(supabaseUrl, supabaseKey);

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

  for (const row of data) {
    cache[row.access_code] = {
      allowance_gb: parseFloat(row.allowance_gb) || 0,
      usage_gb: parseFloat(row.usage_gb) || 0,
    };
  }

  const dbCodes = new Set(data.map(r => r.access_code));
  for (const code of Object.keys(cache)) {
    if (!dbCodes.has(code)) delete cache[code];
  }

  console.log(`[auth] Cache refreshed: ${Object.keys(cache).length} codes`);
}

// ─── Access check (synchronous) ──────────────────────────────────────────────
// skipFreeTrialCheck = true → bypass the proxy whitelist (used for periodic sync)
function checkAccess(accessCode, usageBytes = 0, proxyId = null, skipFreeTrialCheck = false) {
  const record = cache[accessCode];
  if (!record) {
    console.log(`[auth] Denied: ${accessCode} - not found`);
    return false;
  }

  const totalGB = record.usage_gb + (usageBytes / 1e9);
  if (totalGB >= record.allowance_gb) {
    console.log(`[auth] Denied: ${accessCode} - ${totalGB.toFixed(4)}GB used, allowance ${record.allowance_gb}GB`);
    return false;
  }

  // Free‑trial restriction – skip if we're only syncing usage
  if (!skipFreeTrialCheck && accessCode.toLowerCase().includes('freetrial')) {
    if (!proxyId) {
      console.log(`[auth] Denied: ${accessCode} - freetrial requires proxy ID`);
      return false;
    }
    if (!allowedFreeProxies.has(proxyId)) {
      console.log(`[auth] Denied: ${accessCode} - proxy ${proxyId} not whitelisted`);
      return false;
    }
  }

  return true;
}

// ─── Sync usage to Supabase (atomic update) ─────────────────────────────────

async function syncUsage(accessCode, usageBytes) {
  const gb = usageBytes / 1e9;
  if (gb === 0) return;

  const { data, error } = await supabase
    .from('access_codes')
    .select('allowance_gb, usage_gb')
    .eq('access_code', accessCode)
    .single();

  if (error || !data) {
    console.log(`[auth] syncUsage fetch error for ${accessCode}:`, error?.message || 'no data');
    return;
  }

  const currentUsage = parseFloat(data.usage_gb) || 0;
  const currentAllowance = parseFloat(data.allowance_gb) || 0;

  const newUsage = currentUsage + gb;
  const newAllowance = currentAllowance - gb;

  const { error: updateError } = await supabase
    .from('access_codes')
    .update({
      usage_gb: newUsage,
      allowance_gb: newAllowance,
    })
    .eq('access_code', accessCode);

  if (updateError) {
    console.log(`[auth] syncUsage update error for ${accessCode}:`, updateError.message);
    return;
  }

  if (cache[accessCode]) {
    cache[accessCode].usage_gb = newUsage;
    cache[accessCode].allowance_gb = newAllowance;
  } else {
    cache[accessCode] = { usage_gb: newUsage, allowance_gb: newAllowance };
  }

  console.log(`[auth] Synced ${gb.toFixed(4)} GB for ${accessCode} → usage ${newUsage.toFixed(4)}, allowance ${newAllowance.toFixed(4)}`);
}

// ─── Sync proxy usage (unchanged) ──────────────────────────────────────────

async function syncProxyUsage(proxyId, usageBytes) {
  const gb = usageBytes / 1e9;
  if (gb === 0) return;

  const { data, error } = await supabase
    .from('proxy_list')
    .select('usage_gb')
    .eq('proxy_id', proxyId)
    .single();

  if (error || !data) {
    const { error: insertError } = await supabase
      .from('proxy_list')
      .insert({ proxy_id: proxyId, usage_gb: gb });
    if (insertError) {
      console.log(`[auth] syncProxyUsage insert error for ${proxyId}:`, insertError.message);
    } else {
      console.log(`[auth] Inserted proxy ${proxyId} with ${gb.toFixed(4)} GB`);
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
    console.log(`[auth] Synced proxy ${proxyId}: +${gb.toFixed(4)} GB (total ${newTotal.toFixed(4)})`);
  } else {
    console.log(`[auth] syncProxyUsage update error for ${proxyId}:`, updateError.message);
  }
}

// ─── Initialise ──────────────────────────────────────────────────────────────

refreshCache();
setInterval(refreshCache, 30000);

module.exports = { checkAccess, syncUsage, syncProxyUsage };
