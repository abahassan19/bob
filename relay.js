// server.js
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

const wss = new WebSocket.Server({ port: PORT });
wss.setMaxListeners(100); 
const proxies = new Map();
const clients = new Map();
const usage = {};
const proxyUsage = {}; // NEW: per-proxy byte tracking
const PIPE_TIMEOUT = 300000;

console.log(`Relay on ${PORT}`);

// Save proxy list to file on changes
function saveProxyList() {
  const list = {};
  for (const [id] of proxies) {
    list[id] = { connected: true };
  }
  fs.writeFileSync('proxies.json', JSON.stringify(list, null, 2), 'utf8');
}

wss.on('connection', (ws) => {
  ws.on('error', () => {});

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }

    switch (msg.type) {
      case 'register_proxy':
        ws.role = 'proxy';
        ws.proxyId = msg.proxyId;
        proxies.set(msg.proxyId, ws);
        if (!proxyUsage[msg.proxyId]) proxyUsage[msg.proxyId] = 0;
        ws.send(JSON.stringify({ type: 'registered' }));
        console.log(`Proxy online: ${msg.proxyId}`);
        saveProxyList();
        break;

      case 'connect': {
        const proxy = proxies.get(msg.proxyId);
        if (!proxy || proxy.readyState !== WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'error', message: 'proxy unavailable' }));
          return;
        }

        // Auth check (from cache, no DB hit)
        if (!checkAccess(msg.accessCode)) {
          ws.send(JSON.stringify({ type: 'error', message: 'access code not authorized' }));
          console.log(`Auth denied: ${msg.accessCode}`);
          return;
        }

        ws.role = 'client';
        ws.clientId = msg.clientId;
        ws.accessCode = msg.accessCode;

        if (!usage[msg.accessCode]) usage[msg.accessCode] = 0;
        clients.set(msg.clientId, ws);

        proxy.send(JSON.stringify({
          type: 'pipe',
          clientId: msg.clientId,
          targetHost: msg.targetHost,
          targetPort: msg.targetPort,
          accessCode: msg.accessCode
        }));

        const bridge = (proxyWs, clientWs, accessCode, proxyId) => {
          let bytes = 0;
          let alive = true;
          const kill = () => { alive = false; };

          const proxyHandler = (data) => {
            if (!alive) return;
            let m;
            try { m = JSON.parse(data); } catch (e) { return; }
            if (m.type === 'pipe_data' && m.clientId === clientWs.clientId) {
              const len = m.data.length;
              bytes += len;
              proxyUsage[proxyId] = (proxyUsage[proxyId] || 0) + len;
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
              const len = m.data.length;
              bytes += len;
              proxyUsage[proxyId] = (proxyUsage[proxyId] || 0) + len;
              if (proxyWs.readyState === WebSocket.OPEN) {
                proxyWs.send(JSON.stringify({
                  type: 'pipe_data',
                  clientId: clientWs.clientId,
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
            proxyWs.removeListener('message', proxyHandler);
            clientWs.removeListener('message', clientHandler);
            usage[accessCode] = (usage[accessCode] || 0) + bytes;
          };

          clientWs.on('close', cleanup);
          proxyWs.on('close', cleanup);
          ws.on('close', cleanup);

          setTimeout(cleanup, PIPE_TIMEOUT);
        };

        bridge(proxy, ws, msg.accessCode, msg.proxyId);

        ws.send(JSON.stringify({ type: 'proxy_ready' }));
        console.log(`Tunnel: ${msg.proxyId}/${msg.accessCode} -> ${msg.targetHost}:${msg.targetPort}`);
        break;
      }

      case 'usage_update': {
        if (usage[msg.accessCode] !== undefined) {
          usage[msg.accessCode] += msg.bytes;
        }
        break;
      }
    }
  });

  ws.on('close', () => {
    if (ws.role === 'proxy') {
      proxies.delete(ws.proxyId);
      console.log(`Proxy offline: ${ws.proxyId}`);
      delete proxyUsage[ws.proxyId]; // clean up
      saveProxyList();
    } else if (ws.role === 'client') {
      clients.delete(ws.clientId);
    }
  });
});

// Only DB writes happen here - once per minute
setInterval(async () => {
  // Auth sweep before syncing
  const invalid = [];
  for (const code of Object.keys(usage)) {
    if (usage[code] <= 0) continue;
    if (!checkAccess(code)) {
      invalid.push(code);
    }
  }
  for (const code of invalid) {
    console.log(`Auth revoked during sweep: ${code}`);
    delete usage[code];
  }

  // Batch sync everything to Supabase
  for (const [code, bytes] of Object.entries(usage)) {
    if (bytes > 0) {
      await syncUsage(code, bytes);
      usage[code] = 0;
    }
  }

  // NEW: Sync proxy usage
  for (const [proxyId, bytes] of Object.entries(proxyUsage)) {
    if (bytes > 0) {
      await syncProxyUsage(proxyId, bytes);
      proxyUsage[proxyId] = 0;
    }
  }

  // Status log
  console.log(`\nProxies:${proxies.size} Clients:${clients.size}`);
  for (const [code, bytes] of Object.entries(usage)) {
    if (bytes > 0) console.log(`  ${code}: ${(bytes/1e6).toFixed(2)} MB`);
  }
  for (const [proxyId, bytes] of Object.entries(proxyUsage)) {
    if (bytes > 0) console.log(`  Proxy ${proxyId}: ${(bytes/1e6).toFixed(2)} MB`);
  }
}, 60000);