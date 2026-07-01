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
const proxies = new Map(); // proxyId -> { ws, proxyId, connectedAt, lastSeen, ip, bytesRelayed, activeTunnels }
const usage = {};
const proxyUsage = {};
const activeBridges = new Map();
const PIPE_TIMEOUT = 300000;
let bridgeCounter = 0;

// Pending SOCKS5 requests waiting for a proxy to come online
const pendingRequests = new Map(); // proxyId -> Array of { clientSocket, host, port, accessCode, clientId, timer }
const pendingAnyRequests = []; // Array of similar objects for "random" proxy requests
const REQUEST_TIMEOUT = 30000; // 30 seconds

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

// ─── Proxy picker with waiting support ─────────────────────────────────────
// Returns: { found: true, proxyId, proxyEntry } or { found: false, canWait: true/false }
function pickProxy(proxyId) {
  // If "random", we try to find any online proxy
  if (proxyId === 'random') {
    const available = [...proxies.entries()].filter(([_, p]) =>
      p.ws && p.ws.readyState === WebSocket.OPEN
    );
    if (available.length) {
      // Pick a random one
      const idx = Math.floor(Math.random() * available.length);
      const [id, entry] = available[idx];
      return { found: true, proxyId: id, proxyEntry: entry };
    }
    // No online proxy – we can wait for any to come online
    return { found: false, canWait: true, isRandom: true };
  }

  // Specific proxy
  const p = proxies.get(proxyId);
  if (p && p.ws && p.ws.readyState === WebSocket.OPEN) {
    return { found: true, proxyId, proxyEntry: p };
  }

  // Proxy may be registered but offline – we can wait for it
  if (proxies.has(proxyId)) {
    return { found: false, canWait: true, isRandom: false };
  }

  // Proxy never registered – cannot wait
  return { found: false, canWait: false };
}

// ─── Process pending requests for a proxy that just came online ────────────
function processPendingForProxy(proxyId, proxyEntry) {
  const list = pendingRequests.get(proxyId) || [];
  if (list.length === 0) return;

  // We'll take the first pending and process it
  // We'll process one at a time (FIFO) to avoid overloading the proxy
  const req = list.shift();
  if (list.length === 0) pendingRequests.delete(proxyId);

  // Clear the timer
  if (req.timer) clearTimeout(req.timer);

  // Now we can proceed with the connection
  proceedWithConnection(req.clientSocket, proxyId, proxyEntry, req.clientId, req.host, req.port, req.accessCode);
}

// Process any pending "random" requests with the newly connected proxy
function processPendingAny(proxyId, proxyEntry) {
  if (pendingAnyRequests.length === 0) return;
  const req = pendingAnyRequests.shift();
  if (req.timer) clearTimeout(req.timer);
  proceedWithConnection(req.clientSocket, proxyId, proxyEntry, req.clientId, req.host, req.port, req.accessCode);
}

// ─── Actually send SOCKS5 reply and create bridge ─────────────────────────
function proceedWithConnection(clientSocket, proxyId, proxyEntry, clientId, host, port, accessCode) {
  // Send SOCKS5 success reply
  const r = Buffer.alloc(10);
  r[0] = 0x05; r[1] = 0x00; r[2] = 0x00; r[3] = 0x01;
  r.writeUInt32BE(0x7F000001, 4);
  r.writeUInt16BE(0, 8);
  clientSocket.write(r);

  const bridgeId = createBridge(
    clientSocket,
    { ...proxyEntry, proxyId },
    clientId, host, port, accessCode
  );

  console.log(`Tunnel: ${proxyId}/${accessCode} -> ${host}:${port} [bridge#${bridgeId}]`);
}

// ─── Bridge (unchanged) ────────────────────────────────────────────────────
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

// ─── SOCKS5 Server ──────────────────────────────────────────────────────────
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
        sendSocksError(clientSocket, 0x02); // connection not allowed
        die();
        return;
      }

      // Try to pick a proxy
      const pickResult = pickProxy(proxyId);

      if (pickResult.found) {
        // Proxy is online, proceed immediately
        const clientId = `socks:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
        proceedWithConnection(clientSocket, pickResult.proxyId, pickResult.proxyEntry, clientId, host, port, accessCode);
        return;
      }

      // Proxy not found – can we wait?
      if (!pickResult.canWait) {
        // Proxy never registered – cannot wait, reject
        console.log(`Proxy ${proxyId} never registered, rejecting`);
        sendSocksError(clientSocket, 0x04); // host unreachable
        die();
        return;
      }

      // We can wait for the proxy to come online
      const clientId = `socks:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
      const request = {
        clientSocket,
        host,
        port,
        accessCode,
        clientId,
        timer: null
      };

      // Set a timeout to reject if proxy doesn't come back
      const timer = setTimeout(() => {
        // Remove from queue
        if (pickResult.isRandom) {
          const idx = pendingAnyRequests.indexOf(request);
          if (idx !== -1) pendingAnyRequests.splice(idx, 1);
        } else {
          const list = pendingRequests.get(proxyId) || [];
          const idx = list.indexOf(request);
          if (idx !== -1) list.splice(idx, 1);
          if (list.length === 0) pendingRequests.delete(proxyId);
        }
        // Send SOCKS5 error and close
        console.log(`Timeout waiting for proxy ${proxyId} (${accessCode} -> ${host}:${port})`);
        sendSocksError(clientSocket, 0x04); // host unreachable
        die();
      }, REQUEST_TIMEOUT);
      request.timer = timer;

      // Store in appropriate queue
      if (pickResult.isRandom) {
        pendingAnyRequests.push(request);
        console.log(`Queued random request for ${host}:${port} (waiting for any proxy)`);
      } else {
        if (!pendingRequests.has(proxyId)) pendingRequests.set(proxyId, []);
        pendingRequests.get(proxyId).push(request);
        console.log(`Queued request for proxy ${proxyId} (${host}:${port})`);
      }

      // Do NOT send SOCKS5 reply yet – client will wait
    });
  }
});

// Helper to send SOCKS5 error reply
function sendSocksError(socket, code) {
  const r = Buffer.alloc(10);
  r[0] = 0x05;
  r[1] = code; // 0x02 = not allowed, 0x04 = host unreachable, etc.
  r[2] = 0x00;
  r[3] = 0x01;
  r.writeUInt32BE(0, 4);
  r.writeUInt16BE(0, 8);
  try { socket.write(r); } catch {}
}

// ─── HTTP Server ──────────────────────────────────────────────────────────
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

  res.writeHead(404);
  res.end();
});

// ─── WebSocket Server ─────────────────────────────────────────────────────
const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
  ws.on('error', () => {});
  ws.on('ping', () => { ws.pong(); });

  ws.on('pong', () => {
    if (ws.role === 'proxy' && ws.proxyId) {
      updateProxySeen(ws.proxyId);
    }
  });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

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

        // Process any pending requests for this proxy
        const proxyEntry = proxies.get(msg.proxyId);
        processPendingForProxy(msg.proxyId, proxyEntry);
        // Also process one pending "any" request using this proxy
        processPendingAny(msg.proxyId, proxyEntry);
        break;

      case 'usage_update':
        if (usage[msg.accessCode] !== undefined) usage[msg.accessCode] += msg.bytes;
        break;

      case 'ping':
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

      // Optionally, we could keep pending requests for this proxy – they will timeout
      // We could also remove them immediately to free resources, but we'll let timeout handle
    }
  });
});

// ─── Periodic Health Check ──────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [id, p] of proxies) {
    if (now - p.lastSeen > 120000) {
      if (p.ws && p.ws.readyState === WebSocket.OPEN) {
        console.log(`Proxy ${id} stale (lastSeen ${now - p.lastSeen}ms ago), terminating`);
        p.ws.terminate();
      }
    }
  }

  const online = [...proxies.values()].filter(p => p.ws && p.ws.readyState === WebSocket.OPEN).length;
  console.log(`\n[Status] Proxies:${proxies.size}(online:${online}) Bridges:${activeBridges.size} Pending:${pendingRequests.size + pendingAnyRequests.length}`);
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

// ─── Start Servers ──────────────────────────────────────────────────────────
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`HTTP/WS server on 0.0.0.0:${HTTP_PORT}`);
  console.log(`  Proxy backends connect via WebSocket to ws://host:${HTTP_PORT}`);
  console.log(`  GET /healthz, /proxies1234567890`);
});

socksServer.listen(SOCKS_PORT, '0.0.0.0', () => {
  console.log(`SOCKS5 server on 0.0.0.0:${SOCKS_PORT}`);
  console.log(`  curl --socks5 host:${SOCKS_PORT} -U proxyid:accesscode https://example.com`);
  console.log(`  Use username "random" to pick any available proxy`);
});
