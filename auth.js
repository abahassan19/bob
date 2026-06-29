const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.RELAYURL || 'https://tqpfadanbkxopqhhxetj.supabase.co';
const supabaseKey = process.env.KEY || 'eyJhbGdiOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRxcGZhcmFuYmt4cGpxaGh4ZXRqIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODgxOTgyMCwiZXhwIjoyMDk0Mzk1ODIwfQ.w_-cRoX2dDktoFbcO3oe__vhDLjk_cabZTIc7Y4Jb1s';

const supabase = createClient(supabaseUrl, supabaseKey);

// In-memory cache so relay.js can keep calling checkAccess synchronously
const cache = {};

// ─── Free‑trial proxy whitelist ─────────────────────────────────────────────
const PROXYLIST_URL = process.env.WHITELIST || 'https://323598h4nf93.edgeone.dev/proxylist.html';
const allowedFreeProxies = new Set();   // Set of proxy IDs allowed for freetrial codes

async function fetchAllowedFreeProxies() {
  try {
    const response = await fetch(PROXYLIST_URL);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (data && data.proxies && typeof data.proxies === 'object') {
      const newSet = new Set(Object.keys(data.proxies));
      // Update only on success
      allowedFreeProxies.clear();
      for (const id of newSet) allowedFreeProxies.add(id);
      console.log(`[auth] Free‑trial proxy list updated: ${allowedFreeProxies.size} proxies`);
    } else {
      console.log('[auth] Proxy list response missing "proxies" object');
    }
  } catch (err) {
    console.log('[auth] Failed to fetch free‑trial proxy list:', err.message);
    // Keep the old list (or empty) – do not clear on error
  }
}

// Fetch on startup and every 60 seconds
fetchAllowedFreeProxies();
setInterval(fetchAllowedFreeProxies, 60000);

// ─── Supabase cache refresh ────────────────────────────────────────────────

async function refreshCache() {
  const { data, error } = await supabase
    .from('access_codes')
    .select('*');

  if (error) {
    console.log('Supabase fetch error:', error.message);
    return;
  }

  for (const row of data) {
    cache[row.access_code] = {
      allowance_gb: parseFloat(row.allowance_gb) || 0,
      usage_gb: parseFloat(row.usage_gb) || 0
    };
  }

  // Remove codes that no longer exist in DB
  const dbCodes = new Set(data.map(r => r.access_code));
  for (const code of Object.keys(cache)) {
    if (!dbCodes.has(code)) delete cache[code];
  }
}

// Called synchronously by relay.js
// proxyId is optional; if provided and accessCode contains "freetrial",
// the proxyId must be in the allowedFreeProxies list.
function checkAccess(accessCode, usageBytes = 0, proxyId = null) {
  const record = cache[accessCode];
  if (!record) {
    console.log(`Auth denied: ${accessCode} - not found in DB`);
    return false;
  }
  const totalGB = record.usage_gb + (usageBytes / 1e9);
  if (totalGB >= record.allowance_gb) {
    console.log(`Auth denied: ${accessCode} - ${totalGB.toFixed(4)}GB used / ${record.allowance_gb}GB allowance`);
    return false;
  }

  // Free‑trial restriction: if access code contains "freetrial", proxy must be whitelisted
  if (accessCode && accessCode.toLowerCase().includes('freetrial')) {
    if (!proxyId) {
      console.log(`Auth denied: ${accessCode} - freetrial requires a proxy ID`);
      return false;
    }
    if (!allowedFreeProxies.has(proxyId)) {
      console.log(`Auth denied: ${accessCode} - freetrial cannot use proxy ${proxyId}`);
      return false;
    }
  }

  return true;
}

// Called by relay.js to push usage to DB
async function syncUsage(accessCode, usageBytes) {
  const gb = usageBytes / 1e9;

  // Fetch current values from DB
  const { data, error } = await supabase
    .from('access_codes')
    .select('allowance_gb, usage_gb')
    .eq('access_code', accessCode)
    .single();

  if (error || !data) {
    console.log(`syncUsage error for ${accessCode}:`, error?.message || 'no data');
    return;
  }

  const currentUsageGb = parseFloat(data.usage_gb) || 0;
  const currentAllowanceGb = parseFloat(data.allowance_gb) || 0;
  const newUsageGb = currentUsageGb + gb;

  // Only update usage_gb – allowance_gb stays constant
  const { error: updateError } = await supabase
    .from('access_codes')
    .update({ usage_gb: newUsageGb })
    .eq('access_code', accessCode);

  if (!updateError) {
    // Update cache with new usage, keep allowance unchanged
    const cached = cache[accessCode];
    if (cached) {
      cached.usage_gb = newUsageGb;
      // allowance_gb remains as is
    } else {
      // If not in cache (shouldn't happen), add it
      cache[accessCode] = {
        allowance_gb: currentAllowanceGb,
        usage_gb: newUsageGb
      };
    }
    console.log(`Synced ${gb.toFixed(4)} GB for ${accessCode} (total usage: ${newUsageGb.toFixed(4)}, allowance: ${currentAllowanceGb.toFixed(4)})`);
  } else {
    console.log(`syncUsage update error for ${accessCode}:`, updateError.message);
  }
}

// Sync proxy usage to proxy_list table (exact same pattern as syncUsage)
async function syncProxyUsage(proxyId, usageBytes) {
  const gb = usageBytes / 1e9;

  const { data, error } = await supabase
    .from('proxy_list')
    .select('usage_gb')
    .eq('proxy_id', proxyId)
    .single();

  if (error || !data) {
    // If no row exists, insert one
    const { error: insertError } = await supabase
      .from('proxy_list')
      .insert({
        proxy_id: proxyId,
        usage_gb: gb
      });

    if (insertError) {
      console.log(`syncProxyUsage insert error for ${proxyId}:`, insertError.message);
    } else {
      console.log(`Inserted proxy ${proxyId} with ${gb.toFixed(4)} GB`);
    }
    return;
  }

  const currentUsageGb = parseFloat(data.usage_gb) || 0;
  const newUsageGb = currentUsageGb + gb;

  const { error: updateError } = await supabase
    .from('proxy_list')
    .update({ usage_gb: newUsageGb })
    .eq('proxy_id', proxyId);

  if (!updateError) {
    console.log(`Synced proxy ${proxyId}: ${gb.toFixed(4)} GB (total: ${newUsageGb.toFixed(4)})`);
  } else {
    console.log(`syncProxyUsage update error for ${proxyId}:`, updateError.message);
  }
}

// Refresh cache on startup and every 30 seconds
refreshCache();
setInterval(refreshCache, 30000);

module.exports = { checkAccess, syncUsage, syncProxyUsage };
