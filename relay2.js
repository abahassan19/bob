// relay.js — SOCKS5 proxy + WebSocket backend relay
const net = require('net');
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
const usage = {};                // accessCode → accumulated bytes
const proxyUsage = {};           // proxyId → accumulated bytes
const activeBridges = new Map(); // bridgeId → cleanup function
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

// ─── SOCKS5 Server ──────────────────────────────────────────────────────────
// Handles raw TCP connections with SOCKS5 protocol
const socksServer = net.createServer((clientSocket) => {
  let dead = false;
  let proxyId = null;
  let accessCode = null;
  let relay = null;

  const die = () => {
    if (dead) return; dead = true;
    try { clientSocket.destroy(); } catch {}
    try { relay && relay.close(); } catch {}
  };

  clientSocket.on('error', die);

  // ── SOCKS5 Handshake ──
  clientSocket.once('data', (buf) => {
    if (buf[0] !== 0x05) { die(); return; } // Only SOCKS5

    const nmethods = buf[1];
    const methods = buf.slice(2, 2 + nmethods);
    const hasUserPass = methods.includes(0x02);

    if (hasUserPass) {
      // Offer username/password auth
      clientSocket.write(Buffer.from([0x05, 0x02]));

      // Read username/password sub-negotiation
      clientSocket.once('data', (ab) => {
        if (ab[0] !== 0x01) { die(); return; }

        const ulen = ab[1];
        proxyId = ab.slice(2, 2 + ulen).toString();
        const plen = ab[2 + ulen];
        accessCode = ab.slice(3 + ulen, 3 + ulen + plen).toString();

        // Auth status
        clientSocket.write(Buffer.from([0x01, 0x00]));
        doConnect();
      });
    } else {
      // No auth
      if (methods.includes(0x00)) {
        proxyId = 'default';
        accessCode = 'default';
        clientSocket.write(Buffer.from([0x05, 0x00]));
        doConnect();
      } else {
        clientSocket.write(Buffer.from([0x05, 0xFF]));
        die();
      }
    }
  });

  function doConnect() {
    // Read the SOCKS5 connect request
    clientSocket.once('data', (buf) => {
      if (buf[0] !== 0x05 || buf[1] !== 0x01) { die(); return; }

      let host, port;

      if (buf[3] === 0x03) {
        // Domain name
        const dlen = buf[4];
        host = buf.slice(5, 5 + dlen).toString();
        port = buf.readUInt16BE(5 + dlen);
      } else if (buf[3] === 0x01) {
        // IPv4
        host = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
        port = buf.readUInt16BE(8);
      } else if (buf[3] === 0x04) {
        // IPv6
        const parts = [];
        for (let i = 0; i < 8; i++) {
          parts.push(buf.readUInt16BE(4 + i * 2).toString(16));
        }
        host = parts.join(':');
        port = buf.readUInt16BE(20);
      } else {
        die();
        return;
      }

      // Find first available proxy that has this access code authorized
      // We'll try each connected proxy
      const availableProxies = [...proxies.entries()].filter(([_, p]) =>
        p.ws && p.ws.readyState === WebSocket.OPEN
      );

      if (availableProxies.length === 0) {
        console.log(`No proxies available for ${proxyId}:${accessCode} -> ${host}:${port}`);
        // SOCKS5 error: host unreachable
        const r = Buffer.alloc(10);
        r[0] = 0x05; r[1] = 0x04; r[2] = 0x00; r[3] = 0x01;
        r.writeUInt32BE(0, 4); r.writeUInt16BE(0, 8);
        clientSocket.write(r);
        die();
        return;
      }

      if (!checkAccess(accessCode)) {
        console.log(`Auth denied: ${accessCode}`);
        // SOCKS5 error: connection not allowed
        const r = Buffer.alloc(10);
        r[0] = 0x05; r[1] = 0x02; r[2] = 0x00; r[3] = 0x01;
        r.writeUInt32BE(0, 4); r.writeUInt16BE(0, 8);
        clientSocket.write(r);
        die();
        return;
      }

      // Pick the proxy that matches proxyId, or first available if "default"
      let targetProxy;
      if (proxyId === 'default') {
        targetProxy = availableProxies[0];
      } else {
        targetProxy = availableProxies.find(([id]) => id === proxyId);
        if (!targetProxy) targetProxy = availableProxies[0]; // fallback
      }

      const [selectedProxyId, proxyEntry] = targetProxy;

      console.log(`SOCKS5: ${proxyId}:${accessCode} -> ${host}:${port} via proxy ${selectedProxyId}`);

      const clientId = `socks:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
      const proxyWs = proxyEntry.ws;
      const bridgeId = ++bridgeCounter;
      let bytes = 0;
      let alive = true;
      let cleanupTimer = null;

      // Increment active tunnel count
      proxyEntry.activeTunnels = (proxyEntry.activeTunnels || 0) + 1;

      if (!usage[accessCode]) usage[accessCode] = 0;

      // Tell proxy to connect to target
      proxyWs.send(JSON.stringify({
        type: 'pipe',
        clientId,
        targetHost: host,
        targetPort: port,
        accessCode
      }));

      // ── Bridge Logic ──
      const proxyHandler = (data) => {
        if (!alive) return;
        let m;
        try { m = JSON.parse(data); } catch (e) { return; }
        if (m.type === 'pipe_data' && m.clientId === clientId) {
          const buf = Buffer.from(m.data, 'base64');
          bytes += buf.length;
          proxyUsage[selectedProxyId] = (proxyUsage[selectedProxyId] || 0) + buf.length;
          const pEntry = proxies.get(selectedProxyId);
          if (pEntry) {
            pEntry.bytesRelayed = (pEntry.bytesRelayed || 0) + buf.length;
            updateProxySeen(selectedProxyId);
          }
          if (clientSocket.writable) {
            clientSocket.write(buf);
          }
        }
      };

      const sockHandler = (data) => {
        if (!alive) return;
        bytes += data.length;
        proxyUsage[selectedProxyId] = (proxyUsage[selectedProxyId] || 0) + data.length;
        const pEntry = proxies.get(selectedProxyId);
        if (pEntry) {
          pEntry.bytesRelayed = (pEntry.bytesRelayed || 0) + data.length;
        }
        if (proxyWs.readyState === WebSocket.OPEN) {
          proxyWs.send(JSON.stringify({
            type: 'pipe_data',
            clientId,
            data: data.toString('base64')
          }));
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

        const pEntry = proxies.get(selectedProxyId);
        if (pEntry && pEntry.activeTunnels > 0) {
          pEntry.activeTunnels--;
        }

        try { clientSocket.destroy(); } catch {}
        console.log(`Bridge#${bridgeId} closed: ${(bytes/1e6).toFixed(2)} MB`);
      };

      cleanupTimer = setTimeout(cleanup, PIPE_TIMEOUT);
      proxyWs.on('close', cleanup);
      proxyWs.on('error', cleanup);
      clientSocket.on('close', cleanup);
      clientSocket.on('error', cleanup);

      activeBridges.set(bridgeId, cleanup);

      // Send SOCKS5 success response — we send it immediately and let data flow
      const r = Buffer.alloc(10);
      r[0] = 0x05; r[1] = 0x00; r[2] = 0x00; r[3] = 0x01;
      r.writeUInt32BE(0x7F000001, 4); // 127.0.0.1 as bind address
      r.writeUInt16BE(0, 8);          // port 0
      clientSocket.write(r);

      console.log(`Tunnel: ${selectedProxyId}/${accessCode} -> ${host}:${port} [bridge#${bridgeId}]`);
    });
  }

  clientSocket.on('end', die);
});

// ─── HTTP Server (health, stats, WS) ────────────────────────────────────────
const server = http.createServer((req, res) => {
  if (req.url === '/healthz' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
    return;
  }

  if (req.url === '/proxies') {
    const data = getProxyHealth();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      total: Object.keys(data).length,
      proxies: data 
    }, null, 2));
    return;
  }

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
      activeBridges: activeBridges.size,
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
        
        const existing = proxies.get(msg.proxyId);
        if (existing && existing.ws && existing.ws.readyState === WebSocket.OPEN) {
          existing.ws.terminate();
        }

        proxies.set(msg.proxyId, {
          ws,
          connectedAt: Date.now(),
          lastSeen: Date.now(),
          ip: req.socket.remoteAddress || 'unknown',
          bytesRelayed: 0,
          activeTunnels: 0
        });
        
        if (!proxyUsage[msg.proxyId]) proxyUsage[msg.proxyId] = 0;
        
        ws.send(JSON.stringify({ 
          type: 'registered',
          host: req.headers.host ? req.headers.host.split(':')[0] : req.socket.localAddress,
          port: PORT
        }));
        console.log(`Proxy online: ${msg.proxyId} from ${req.socket.remoteAddress}`);
        saveProxyList();
        break;

      case 'usage_update': {
        if (usage[msg.accessCode] !== undefined) {
          usage[msg.accessCode] += msg.bytes;
        }
        break;
      }

      case 'ping': {
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
  });
});

// ─── Connection Multiplexer ──────────────────────────────────────────────────
// Sits on PORT, detects SOCKS5 vs HTTP/WS
const multiplexer = net.createServer((socket) => {
  socket.once('data', (firstByte) => {
    // SOCKS5 starts with 0x05
    // HTTP starts with G(0x47), P(0x50), etc
    const isSocks = firstByte[0] === 0x05;
    const isHttp = (
      firstByte[0] === 0x47 || // GET
      firstByte[0] === 0x50 || // POST/PUT
      firstByte[0] === 0x44 || // DELETE
      firstByte[0] === 0x48 || // HEAD
      firstByte[0] === 0x4F || // OPTIONS
      firstByte[0] === 0x43 || // CONNECT
      firstByte[0] === 0x54    // TRACE
    );

    socket.unshift(firstByte);

    if (isSocks) {
      socksServer.emit('connection', socket);
    } else if (isHttp) {
      server.emit('connection', socket);
    } else {
      // Unknown — treat as SOCKS to be safe
      socksServer.emit('connection', socket);
    }
  });

  socket.on('error', () => {});
});

// ─── Periodic Health Check & Cleanup ────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  
  for (const [id, p] of proxies) {
    if (now - p.lastSeen > 60000) {
      const ws = p.ws;
      if (ws && ws.readyState === WebSocket.OPEN) {
        console.log(`Proxy ${id} stale (${Math.floor((now - p.lastSeen)/1000)}s), terminating`);
        ws.terminate();
      }
    }
  }

  const proxyCount = proxies.size;
  const bridgeCount = activeBridges.size;
  
  const onlineProxies = [...proxies.entries()].filter(([_, p]) => 
    p.ws && p.ws.readyState === WebSocket.OPEN
  ).length;

  console.log(`\n[Status] Proxies:${proxyCount}(online:${onlineProxies}) Bridges:${bridgeCount}`);
  
  for (const [id, p] of proxies) {
    const alive = p.ws && p.ws.readyState === WebSocket.OPEN;
    const idle = Math.floor((now - p.lastSeen) / 1000);
    console.log(`  ${alive ? '●' : '○'} ${id} | ${idle}s idle | ${p.activeTunnels || 0} tunnels | ${(p.bytesRelayed/1e6).toFixed(2)} MB`);
  }

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
}, 30000);

// ─── Start ───────────────────────────────────────────────────────────────────
multiplexer.listen(PORT, '0.0.0.0', () => {
  console.log(`Relay listening on 0.0.0.0:${PORT}`);
  console.log(`  SOCKS5  :${PORT}  — curl --socks5 ... -U proxyid:accesscode`);
  console.log(`  HTTP/WS :${PORT}  — health, stats, proxy backend connections`);
  console.log(`  GET /         - Health check`);
  console.log(`  GET /proxies  - JSON list of proxies`);
  console.log(`  GET /stats    - Full stats`);
});
