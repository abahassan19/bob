// relay.js
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const { checkAccess, syncUsage, syncProxyUsage } = require('./auth');
const PORT = process.env.PORT || 10000;

process.on('uncaughtException', (err) => {
  console.error('Uncaught:', err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason.message);
});

// ─── State ───────────────────────────────────────────────────────────────────
const proxies = new Map();       // proxyId → { ws, connectedAt, lastSeen, ip, bytesRelayed }
const clients = new Map();       // clientId → { ws, proxyId, accessCode, connectedAt, bytes }
const usage = {};                // accessCode → accumulated bytes
const proxyUsage = {};           // proxyId → accumulated bytes
const activeBridges = new Map(); // bridgeId → bridge cleanup function
const PIPE_TIMEOUT = 300000;
let bridgeCounter = 0;

console.log(`Relay on ${PORT}`);

// ─── Proxy Health Tracking ───────────────────────────────────────────────────
function updateProxySeen(proxyId) {
  const p = proxies.get(proxyId);
  if (p) p.lastSeen = Date.now();
}

function getProxyHealth() {
  const now = Date.now();
  const list = {};
  for (const [id, p] of proxies) {
    const wsAlive = p.ws && p.ws.readyState === WebSocket.OPEN;
    const sinceMs = now - p.connectedAt;
    const lastSeenMs = now - p.lastSeen;
    list[id] = {
      connected: wsAlive,
      uptime: Math.floor(sinceMs / 1000),
      lastSeen: Math.floor(lastSeenMs / 1000) + 's ago',
      ip: p.ip,
      bytesRelayed: p.bytesRelayed,
      activeTunnels: p.activeTunnels || 0
    };
  }
  return list;
}

function saveProxyList() {
  const list = {};
  for (const [id] of proxies) {
    list[id] = { connected: true };
  }
  fs.writeFileSync('proxies.json', JSON.stringify(list, null, 2), 'utf8');
}

// ─── HTTP Server ─────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  if (req.url === '/healthz' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
    return;
  }

  // ── Proxy list endpoint ──
  if (req.url === '/proxies') {
    const data = getProxyHealth();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      total: Object.keys(data).length,
      proxies: data 
    }, null, 2));
    return;
  }

  // ── Stats endpoint ──
  if (req.url === '/stats') {
    const proxyHealth = getProxyHealth();
    const usageSummary = {};
    for (const [code, bytes] of Object.entries(usage)) {
      if (bytes > 0) usageSummary[code] = (bytes / 1e6).toFixed(2) + ' MB';
    }
    const proxyUsageSummary = {};
    for (const [id, bytes] of Object.entries(proxyUsage)) {
      if (bytes > 0) proxyUsageSummary[id] = (bytes / 1e6).toFixed(2) + ' MB';
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      proxies: proxyHealth,
      clients: clients.size,
      usage: usageSummary,
      proxyUsage: proxyUsageSummary
    }, null, 2));
    return;
  }

  res.writeHead(404);
  res.end();
});

// ─── WebSocket Server ────────────────────────────────────────────────────────
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  ws.on('error', () => {});
  ws.on('ping', () => { ws.pong(); });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    switch (msg.type) {
      // ── Proxy Registration ──
      case 'register_proxy':
        ws.role = 'proxy';
        ws.proxyId = msg.proxyId;
        
        proxies.set(msg.proxyId, {
          ws,
          connectedAt: Date.now(),
          lastSeen: Date.now(),
          ip: req.socket.remoteAddress || 'unknown',
          bytesRelayed: 0,
          activeTunnels: 0
        });
        
        if (!proxyUsage[msg.proxyId]) proxyUsage[msg.proxyId] = 0;
        ws.send(JSON.stringify({ type: 'registered' }));
        console.log(`Proxy online: ${msg.proxyId} from ${req.socket.remoteAddress}`);
        saveProxyList();
        break;

      // ── Client Connect ──
      case 'connect': {
        const proxyEntry = proxies.get(msg.proxyId);
        if (!proxyEntry || !proxyEntry.ws || proxyEntry.ws.readyState !== WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'error', message: 'proxy unavailable' }));
          return;
        }

        if (!checkAccess(msg.accessCode)) {
          ws.send(JSON.stringify({ type: 'error', message: 'access code not authorized' }));
          console.log(`Auth denied: ${msg.accessCode}`);
          return;
        }

        ws.role = 'client';
        ws.clientId = msg.clientId;
        ws.accessCode = msg.accessCode;
        ws.proxyId = msg.proxyId;

        if (!usage[msg.accessCode]) usage[msg.accessCode] = 0;
        clients.set(msg.clientId, {
          ws,
          proxyId: msg.proxyId,
          accessCode: msg.accessCode,
          connectedAt: Date.now(),
          bytes: 0
        });

        // Increment active tunnel count on proxy
        proxyEntry.activeTunnels = (proxyEntry.activeTunnels || 0) + 1;

        const proxyWs = proxyEntry.ws;
        const clientWs = ws;
        const accessCode = msg.accessCode;
        const proxyId = msg.proxyId;
        const clientId = msg.clientId;
        const bridgeId = ++bridgeCounter;

        proxyWs.send(JSON.stringify({
          type: 'pipe',
          clientId: msg.clientId,
          targetHost: msg.targetHost,
          targetPort: msg.targetPort,
          accessCode: msg.accessCode
        }));

        // ── Bridge Logic ──
        let bytes = 0;
        let alive = true;
        let cleanupTimer = null;

        const proxyHandler = (data) => {
          if (!alive) return;
          let m;
          try { m = JSON.parse(data); } catch (e) { return; }
          if (m.type === 'pipe_data' && m.clientId === clientId) {
            const len = Buffer.from(m.data, 'base64').length;
            bytes += len;
            proxyUsage[proxyId] = (proxyUsage[proxyId] || 0) + len;
            const pEntry = proxies.get(proxyId);
            if (pEntry) {
              pEntry.bytesRelayed = (pEntry.bytesRelayed || 0) + len;
              updateProxySeen(proxyId);
            }
            if (clientWs.readyState === WebSocket.OPEN) {
              clientWs.send(JSON.stringify({ type: 'pipe_data', data: m.data }));
            }
          }
        };

        const clientHandler = (data) => {
          if (!alive) return;
          let m;
          try { m = JSON.parse(data); } catch (e) { return; }
          if (m.type === 'pipe_data') {
            const len = Buffer.from(m.data, 'base64').length;
            bytes += len;
            proxyUsage[proxyId] = (proxyUsage[proxyId] || 0) + len;
            const pEntry = proxies.get(proxyId);
            if (pEntry) {
              pEntry.bytesRelayed = (pEntry.bytesRelayed || 0) + len;
            }
            if (proxyWs.readyState === WebSocket.OPEN) {
              proxyWs.send(JSON.stringify({
                type: 'pipe_data',
                clientId: clientId,
                data: m.data
              }));
            }
          }
        };

        proxyWs.on('message', proxyHandler);
        clientWs.on('message', clientHandler);

        const cleanup = () => {
          if (!alive) return;
          alive = false;
          activeBridges.delete(bridgeId);
          if (cleanupTimer) { clearTimeout(cleanupTimer); cleanupTimer = null; }
          proxyWs.removeListener('message', proxyHandler);
          proxyWs.removeListener('close', cleanup);
          proxyWs.removeListener('error', cleanup);
          clientWs.removeListener('message', clientHandler);
          clientWs.removeListener('close', cleanup);
          clientWs.removeListener('error', cleanup);
          
          usage[accessCode] = (usage[accessCode] || 0) + bytes;
          
          // Decrement active tunnel count
          const pEntry = proxies.get(proxyId);
          if (pEntry && pEntry.activeTunnels > 0) {
            pEntry.activeTunnels--;
          }
          
          clients.delete(clientId);
        };

        cleanupTimer = setTimeout(cleanup, PIPE_TIMEOUT);
        proxyWs.on('close', cleanup);
        proxyWs.on('error', cleanup);
        clientWs.on('close', cleanup);
        clientWs.on('error', cleanup);
        
        activeBridges.set(bridgeId, cleanup);

        ws.send(JSON.stringify({ type: 'proxy_ready' }));
        console.log(`Tunnel: ${proxyId}/${accessCode} -> ${msg.targetHost}:${msg.targetPort} [bridge#${bridgeId}]`);
        break;
      }

      case 'usage_update': {
        if (usage[msg.accessCode] !== undefined) {
          usage[msg.accessCode] += msg.bytes;
        }
        break;
      }

      case 'ping': {
        // Client-side ping for proxy backends
        if (ws.role === 'proxy' && ws.proxyId) {
          updateProxySeen(ws.proxyId);
          ws.send(JSON.stringify({ type: 'pong' }));
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    if (ws.role === 'proxy') {
      const pEntry = proxies.get(ws.proxyId);
      if (pEntry) {
        console.log(`Proxy offline: ${ws.proxyId} (relayed ${(pEntry.bytesRelayed/1e6).toFixed(2)} MB, ${pEntry.activeTunnels} tunnels active)`);
      }
      proxies.delete(ws.proxyId);
      delete proxyUsage[ws.proxyId];
      saveProxyList();
    }
    
    if (ws.role === 'client' && ws.clientId) {
      clients.delete(ws.clientId);
    }
    
    // Clean up any bridges associated with this ws
    // (bridges have their own close handlers that do cleanup)
  });
});

// ─── Periodic Health Check & Cleanup ────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  
  // Check for stale proxies (no message in 60s)
  for (const [id, p] of proxies) {
    if (now - p.lastSeen > 60000) {
      const ws = p.ws;
      if (ws && ws.readyState === WebSocket.OPEN) {
        console.log(`Proxy ${id} stale (${Math.floor((now - p.lastSeen)/1000)}s), terminating`);
        ws.terminate();
      }
    }
  }

  // Log stats
  const proxyCount = proxies.size;
  const clientCount = clients.size;
  const bridgeCount = activeBridges.size;
  
  const onlineProxies = [...proxies.entries()].filter(([_, p]) => 
    p.ws && p.ws.readyState === WebSocket.OPEN
  ).length;

  console.log(`\n[Status] Proxies:${proxyCount}(online:${onlineProxies}) Clients:${clientCount} Bridges:${bridgeCount}`);
  
  // List all proxies and their tunnels
  for (const [id, p] of proxies) {
    const alive = p.ws && p.ws.readyState === WebSocket.OPEN;
    const idle = Math.floor((now - p.lastSeen) / 1000);
    console.log(`  ${alive ? '●' : '○'} ${id} | ${idle}s idle | ${p.activeTunnels || 0} tunnels | ${(p.bytesRelayed/1e6).toFixed(2)} MB`);
  }

  // ── Auth sync ──
  (async () => {
    const invalid = [];
    for (const code of Object.keys(usage)) {
      if (usage[code] <= 0) continue;
      if (!checkAccess(code)) invalid.push(code);
    }
    for (const code of invalid) {
      console.log(`Auth revoked during sweep: ${code}`);
      delete usage[code];
    }

    for (const [code, bytes] of Object.entries(usage)) {
      if (bytes > 0) {
        await syncUsage(code, bytes);
        usage[code] = 0;
      }
    }

    for (const [proxyId, bytes] of Object.entries(proxyUsage)) {
      if (bytes > 0) {
        await syncProxyUsage(proxyId, bytes);
        proxyUsage[proxyId] = 0;
      }
    }
  })();
}, 30000); // Check every 30s instead of 60s for faster reaction

// ─── Start ───────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Relay HTTP+WS server listening on 0.0.0.0:${PORT}`);
  console.log(`Endpoints:`);
  console.log(`  GET /         - Health check`);
  console.log(`  GET /proxies  - JSON list of all proxies with status`);
  console.log(`  GET /stats    - Full stats JSON`);
  console.log(`  WS  /         - WebSocket for proxy backends and clients`);
});
