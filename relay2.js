// relay.js — SOCKS5 on 1080, WebSocket on 10000
const net = require('net');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const { checkAccess, syncUsage, syncProxyUsage } = require('./auth');

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '10000');
const SOCKS_PORT = parseInt(process.env.SOCKS_PORT || '1080');

process.on('uncaughtException', (err) => {
  console.error('Uncaught:', err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason.message);
});

// ─── State ───────────────────────────────────────────────────────────────────
const proxies = new Map();
const usage = {};
const proxyUsage = {};
const activeBridges = new Map();
const PIPE_TIMEOUT = 300000;
let bridgeCounter = 0;

// ─── Proxy Health ────────────────────────────────────────────────────────────
function updateProxySeen(proxyId) {
  const p = proxies.get(proxyId);
  if (p) p.lastSeen = Date.now();
}

function getProxyHealth() {
  const now = Date.now();
  const list = {};
  for (const [id, p] of proxies) {
    list[id] = {
      connected: p.ws && p.ws.readyState === WebSocket.OPEN,
      uptime: Math.floor((now - p.connectedAt) / 1000),
      lastSeen: Math.floor((now - p.lastSeen) / 1000) + 's ago',
      ip: p.ip,
      bytesRelayed: p.bytesRelayed,
      activeTunnels: p.activeTunnels || 0
    };
  }
  return list;
}

function saveProxyList() {
  const list = {};
  for (const [id] of proxies) list[id] = { connected: true };
  fs.writeFileSync('proxies.json', JSON.stringify(list, null, 2), 'utf8');
}

// ─── Strict proxy picker (NO FALLBACK) ─────────────────────────────────────
function pickProxy(proxyId) {
  if (!proxyId || proxyId === 'default') {
    const available = [...proxies.entries()].filter(([_, p]) =>
      p.ws && p.ws.readyState === WebSocket.OPEN
    );
    return available.length ? available[0] : null;
  }

  const p = proxies.get(proxyId);
  if (p && p.ws && p.ws.readyState === WebSocket.OPEN) {
    return [proxyId, p];
  }
  console.log(`[pickProxy] Requested proxy "${proxyId}" is offline or not registered`);
  return null;
}

// ─── Bridge ─────────────────────────────────────────────────────────────────
function createBridge(clientSocket, proxyEntry, clientId, host, port, accessCode) {
  const proxyWs = proxyEntry.ws;
  const proxyId = proxyEntry.proxyId;
  const bridgeId = ++bridgeCounter;
  let bytes = 0;
  let alive = true;
  let cleanupTimer = null;

  proxyEntry.activeTunnels = (proxyEntry.activeTunnels || 0) + 1;
  if (!usage[accessCode]) usage[accessCode] = 0;

  proxyWs.send(JSON.stringify({
    type: 'pipe',
    clientId,
    targetHost: host,
    targetPort: port,
    accessCode
  }));

  const proxyHandler = (data) => {
    if (!alive) return;
    let m;
    try { m = JSON.parse(data); } catch { return; }
    if (m.type === 'pipe_data' && m.clientId === clientId) {
      const buf = Buffer.from(m.data, 'base64');
      bytes += buf.length;
      proxyUsage[proxyId] = (proxyUsage[proxyId] || 0) + buf.length;
      const p = proxies.get(proxyId);
      if (p) { p.bytesRelayed = (p.bytesRelayed || 0) + buf.length; updateProxySeen(proxyId); }
      if (clientSocket.writable) {
        try { clientSocket.write(buf); } catch {}
      }
    }
  };

  const sockHandler = (data) => {
    if (!alive) return;
    bytes += data.length;
    proxyUsage[proxyId] = (proxyUsage[proxyId] || 0) + data.length;
    const p = proxies.get(proxyId);
    if (p) p.bytesRelayed = (p.bytesRelayed || 0) + data.length;
    if (proxyWs.readyState === WebSocket.OPEN) {
      proxyWs.send(JSON.stringify({ type: 'pipe_data', clientId, data: data.toString('base64') }));
    }
  };

  proxyWs.on('message', proxyHandler);
  clientSocket.on('data', sockHandler);

  const cleanup = () => {
    if (!alive) return;
    alive = false;
    activeBridges.delete(bridgeId);
    if (cleanupTimer) { clearTimeout(cleanupTimer); cleanupTimer = null; }
    proxyWs.removeListener('message', proxyHandler);
    proxyWs.removeListener('close', cleanup);
    proxyWs.removeListener('error', cleanup);
    clientSocket.removeListener('data', sockHandler);
    clientSocket.removeListener('close', cleanup);
    clientSocket.removeListener('error', cleanup);
    usage[accessCode] = (usage[accessCode] || 0) + bytes;
    const p = proxies.get(proxyId);
    if (p && p.activeTunnels > 0) p.activeTunnels--;
    try { clientSocket.destroy(); } catch {}
    console.log(`Bridge#${bridgeId} closed: ${(bytes/1e6).toFixed(2)} MB`);
  };

  cleanupTimer = setTimeout(cleanup, PIPE_TIMEOUT);
  proxyWs.on('close', cleanup);
  proxyWs.on('error', cleanup);
  clientSocket.on('close', cleanup);
  clientSocket.on('error', cleanup);
  activeBridges.set(bridgeId, cleanup);

  return bridgeId;
}

// ─── SOCKS5 Server (port 1080) ──────────────────────────────────────────────
const socksServer = net.createServer((clientSocket) => {
  let dead = false;
  let proxyId = null;
  let accessCode = null;

  const die = () => {
    if (dead) return; dead = true;
    try { clientSocket.destroy(); } catch {}
  };

  clientSocket.on('error', die);

  // Phase 1: Greeting
  clientSocket.once('data', (buf) => {
    if (buf.length < 2 || buf[0] !== 0x05) { console.log('Not SOCKS5, closing'); die(); return; }

    const nmethods = buf[1];
    if (buf.length < 2 + nmethods) { die(); return; }

    const methods = [];
    for (let i = 0; i < nmethods; i++) methods.push(buf[2 + i]);

    if (methods.includes(0x02)) {
      clientSocket.write(Buffer.from([0x05, 0x02]));

      clientSocket.once('data', (ab) => {
        if (ab.length < 2 || ab[0] !== 0x01) { die(); return; }
        const ulen = ab[1];
        if (ab.length < 2 + ulen + 1) { die(); return; }
        proxyId = ab.slice(2, 2 + ulen).toString();
        const plen = ab[2 + ulen];
        if (ab.length < 3 + ulen + plen) { die(); return; }
        accessCode = ab.slice(3 + ulen, 3 + ulen + plen).toString();
        clientSocket.write(Buffer.from([0x01, 0x00]));
        console.log(`SOCKS5 auth: ${proxyId}:${accessCode}`);
        doConnect();
      });

    } else if (methods.includes(0x00)) {
      proxyId = 'default';
      accessCode = 'default';
      clientSocket.write(Buffer.from([0x05, 0x00]));
      doConnect();
    } else {
      clientSocket.write(Buffer.from([0x05, 0xFF]));
      die();
    }
  });

  function doConnect() {
    clientSocket.once('data', (buf) => {
      if (buf.length < 4 || buf[0] !== 0x05 || buf[1] !== 0x01) { die(); return; }

      let host, port;

      switch (buf[3]) {
        case 0x01:
          if (buf.length < 10) { die(); return; }
          host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
          port = buf.readUInt16BE(8);
          break;
        case 0x03:
          const dlen = buf[4];
          if (buf.length < 5 + dlen + 2) { die(); return; }
          host = buf.slice(5, 5 + dlen).toString();
          port = buf.readUInt16BE(5 + dlen);
          break;
        case 0x04:
          if (buf.length < 22) { die(); return; }
          const parts = [];
          for (let i = 0; i < 8; i++) parts.push(buf.readUInt16BE(4 + i * 2).toString(16));
          host = parts.join(':');
          port = buf.readUInt16BE(20);
          break;
        default: die(); return;
      }

      console.log(`SOCKS5 connect: ${proxyId}:${accessCode} -> ${host}:${port}`);

      if (!checkAccess(accessCode, 0, proxyId)) {
        const r = Buffer.alloc(10);
        r[0] = 0x05; r[1] = 0x02; r[2] = 0x00; r[3] = 0x01;
        r.writeUInt32BE(0, 4); r.writeUInt16BE(0, 8);
        clientSocket.write(r);
        die();
        return;
      }

      const picked = pickProxy(proxyId);
      if (!picked) {
        const r = Buffer.alloc(10);
        r[0] = 0x05; r[1] = 0x04; r[2] = 0x00; r[3] = 0x01;
        r.writeUInt32BE(0, 4); r.writeUInt16BE(0, 8);
        clientSocket.write(r);
        die();
        return;
      }

      const [selectedProxyId, proxyEntry] = picked;
      const clientId = `socks:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;

      const r = Buffer.alloc(10);
      r[0] = 0x05; r[1] = 0x00; r[2] = 0x00; r[3] = 0x01;
      r.writeUInt32BE(0x7F000001, 4);
      r.writeUInt16BE(0, 8);
      clientSocket.write(r);

      const bridgeId = createBridge(
        clientSocket,
        { ...proxyEntry, proxyId: selectedProxyId },
        clientId, host, port, accessCode
      );

      console.log(`Tunnel: ${selectedProxyId}/${accessCode} -> ${host}:${port} [bridge#${bridgeId}]`);
    });
  }
});

// ─── HTTP Server (port 10000 — health, stats, WS) ───────────────────────────
const httpServer = http.createServer((req, res) => {
  if (req.url === '/healthz' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
    return;
  }

  if (req.url === '/proxies1234567890') {
    const data = getProxyHealth();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total: Object.keys(data).length, proxies: data }));
    return;
  }

  if (req.url === '/stats1234567890stats') {
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
      activeBridges: activeBridges.size,
      usage: usageSummary,
      proxyUsage: proxyUsageSummary
    }));
    return;
  }

  res.writeHead(404);
  res.end();
});

// ─── WebSocket Server (proxy backends connect here) ─────────────────────────
const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
  ws.on('error', () => {});
  ws.on('ping', () => { ws.pong(); });

  // Keep lastSeen fresh on any WebSocket pong (proxy sends ping frames)
  ws.on('pong', () => {
    if (ws.role === 'proxy' && ws.proxyId) {
      updateProxySeen(ws.proxyId);
    }
  });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // Update lastSeen on any JSON message from proxy
    if (ws.role === 'proxy' && ws.proxyId) {
      updateProxySeen(ws.proxyId);
    }

    switch (msg.type) {
      case 'register_proxy':
        ws.role = 'proxy';
        ws.proxyId = msg.proxyId;

        const existing = proxies.get(msg.proxyId);
        if (existing && existing.ws && existing.ws.readyState === WebSocket.OPEN) {
          existing.ws.terminate();
        }

        proxies.set(msg.proxyId, {
          ws,
          proxyId: msg.proxyId,
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

      case 'usage_update':
        if (usage[msg.accessCode] !== undefined) usage[msg.accessCode] += msg.bytes;
        break;

      case 'ping':
        // Application-level ping (not used by proxy, but handle anyway)
        if (ws.role === 'proxy' && ws.proxyId) {
          updateProxySeen(ws.proxyId);
          ws.send(JSON.stringify({ type: 'pong' }));
        }
        break;
    }
  });

  ws.on('close', () => {
    if (ws.role === 'proxy') {
      const p = proxies.get(ws.proxyId);
      if (p) {
        console.log(`Proxy offline: ${ws.proxyId} (relayed ${(p.bytesRelayed/1e6).toFixed(2)} MB, ${p.activeTunnels} tunnels)`);
      }
      proxies.delete(ws.proxyId);
      delete proxyUsage[ws.proxyId];
      saveProxyList();
    }
  });
});

// ─── Periodic Health Check ──────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [id, p] of proxies) {
    // If lastSeen is older than 120 seconds, consider it dead
    if (now - p.lastSeen > 120000) {
      if (p.ws && p.ws.readyState === WebSocket.OPEN) {
        console.log(`Proxy ${id} stale (lastSeen ${now - p.lastSeen}ms ago), terminating`);
        p.ws.terminate();
      }
    }
  }

  const online = [...proxies.values()].filter(p => p.ws && p.ws.readyState === WebSocket.OPEN).length;
  console.log(`\n[Status] Proxies:${proxies.size}(online:${online}) Bridges:${activeBridges.size}`);
  for (const [id, p] of proxies) {
    const alive = p.ws && p.ws.readyState === WebSocket.OPEN;
    console.log(`  ${alive ? '●' : '○'} ${id} | ${Math.floor((now - p.lastSeen)/1000)}s idle | ${p.activeTunnels || 0} tunnels | ${(p.bytesRelayed/1e6).toFixed(2)} MB`);
  }

  (async () => {
    const invalid = [];
    for (const code of Object.keys(usage)) {
      if (usage[code] <= 0) continue;
      if (!checkAccess(code, 0, null, true)) invalid.push(code);
    }
    for (const code of invalid) { console.log(`Auth revoked: ${code}`); delete usage[code]; }
    for (const [code, bytes] of Object.entries(usage)) {
      if (bytes > 0) { await syncUsage(code, bytes); usage[code] = 0; }
    }
    for (const [pid, bytes] of Object.entries(proxyUsage)) {
      if (bytes > 0) { await syncProxyUsage(pid, bytes); proxyUsage[pid] = 0; }
    }
  })();
}, 30000);

// ─── Start Both Servers ─────────────────────────────────────────────────────
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`HTTP/WS server on 0.0.0.0:${HTTP_PORT}`);
  console.log(`  Proxy backends connect via WebSocket to ws://host:${HTTP_PORT}`);
  console.log(`  GET /healthz, /proxies, /stats`);
});

socksServer.listen(SOCKS_PORT, '0.0.0.0', () => {
  console.log(`SOCKS5 server on 0.0.0.0:${SOCKS_PORT}`);
  console.log(`  curl --socks5 host:${SOCKS_PORT} -U proxyid:accesscode https://example.com`);
});
