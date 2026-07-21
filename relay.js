// relay.js — SOCKS5 on 1080, WebSocket on 10000, UDP/QUIC on one port
const net = require('net');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const dgram = require('dgram');
const dns = require('dns');
const { checkAccess, syncUsage, syncProxyUsage } = require('./auth');

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '10000');
const SOCKS_PORT = parseInt(process.env.SOCKS_PORT || '1080');
const UDP_PORT = parseInt(process.env.UDP_PORT || '11000');
const UDP_HOST = process.env.UDP_HOST || (process.env.FLY_APP_NAME ? 'fly-global-services' : '0.0.0.0');

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

const pendingRequests = new Map();
const pendingAnyRequests = [];
const REQUEST_TIMEOUT = 30000;

// ─── UDP/QUIC State ──────────────────────────────────────────────────────────
const udpSessions = new Map();
const udpAssociations = new Map();
let udpSocket = null;

// ─── UDP Session Class ───────────────────────────────────────────────────────
class UdpSession {
  constructor(clientKey, clientRinfo, proxyId, accessCode) {
    this.clientKey = clientKey;
    this.clientRinfo = clientRinfo;
    this.proxyId = proxyId;
    this.accessCode = accessCode;
    this.targetHost = null;
    this.targetPort = null;
    this.outSocket = null;
    this.bytesRelayed = 0;
    this.proxyUsage = 0;
    this.lastActivity = Date.now();
    this.createdAt = Date.now();
    this.alive = true;
    this.idleTimer = null;
    this.resetIdleTimer();
    console.log(`UDP session create: ${clientKey} (${proxyId}:${accessCode})`);
  }

  resetIdleTimer() {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      console.log(`UDP session idle timeout: ${this.clientKey}`);
      this.close();
    }, 300000);
  }

  setTarget(host, port) {
    if (this.targetHost !== host || this.targetPort !== port) {
      this.closeOutSocket();
      this.targetHost = host;
      this.targetPort = port;
    }
  }

  ensureOutSocket() {
    if (this.outSocket) return this.outSocket;
    if (!this.targetHost || !this.targetPort) return null;
    const sock = dgram.createSocket('udp4');
    sock.session = this;
    sock.on('error', (err) => {
      console.error(`UDP out ${this.clientKey} -> ${this.targetHost}:${this.targetPort} err:`, err.message);
      try { sock.close(); } catch {}
      if (this.outSocket === sock) this.outSocket = null;
    });
    sock.on('message', (resp) => {
      if (!this.alive) return;
      this.lastActivity = Date.now();
      this.resetIdleTimer();
      this.bytesRelayed += resp.length;
      sendUdpResponse(this, this.targetHost, this.targetPort, resp);
    });
    this.outSocket = sock;
    return sock;
  }

  closeOutSocket() {
    if (this.outSocket) {
      try { this.outSocket.close(); } catch {}
      this.outSocket = null;
    }
  }

  close() {
    if (!this.alive) return;
    this.alive = false;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.closeOutSocket();
    udpSessions.delete(this.clientKey);
    if (this.accessCode && this.proxyUsage > 0) {
      usage[this.accessCode] = (usage[this.accessCode] || 0) + this.proxyUsage;
    }
    console.log(`UDP session close: ${this.clientKey} (${(this.bytesRelayed/1e6).toFixed(2)} MB)`);
  }

  forwardDatagram(payload, host, port) {
    if (!this.alive) return;
    this.lastActivity = Date.now();
    this.resetIdleTimer();
    this.setTarget(host, port);
    const sock = this.ensureOutSocket();
    if (!sock) return;
    this.bytesRelayed += payload.length;
    this.proxyUsage += payload.length;
    sock.send(payload, 0, payload.length, port, host, (err) => {
      if (err) {
        console.error(`UDP send ${host}:${port} err:`, err.message);
        this.closeOutSocket();
      }
    });
  }
}

// ─── UDP Listener ──────────────────────────────────────────────────────────────
function initUdpListener() {
  udpSocket = dgram.createSocket({
    type: 'udp4',
    lookup: (host, opts, cb) => {
      dns.lookup(host, opts, cb);
    }
  });

  udpSocket.on('error', (err) => {
    console.error('UDP socket error:', err.message);
    setTimeout(initUdpListener, 5000);
  });

  udpSocket.on('message', (msg, rinfo) => {
    const clientKey = `${rinfo.address}:${rinfo.port}`;
    let session = udpSessions.get(clientKey);
    if (!session) {
      console.log(`UDP drop (no ASSOCIATE): ${clientKey}`);
      return;
    }
    if (rinfo.address !== session.clientRinfo.address || rinfo.port !== session.clientRinfo.port) {
      const oldKey = session.clientKey;
      session.clientKey = clientKey;
      session.clientRinfo = rinfo;
      udpSessions.delete(oldKey);
      udpSessions.set(clientKey, session);
      console.log(`UDP migration: ${oldKey} -> ${clientKey}`);
    }
    if (msg.length < 4) return;
    if (msg[2] !== 0) {
      console.warn(`UDP frag=${msg[2]} not supported, drop`);
      return;
    }
    let host, port, off;
    switch (msg[3]) {
      case 0x01:
        if (msg.length < 10) return;
        host = `${msg[4]}.${msg[5]}.${msg[6]}.${msg[7]}`;
        port = msg.readUInt16BE(8);
        off = 10;
        break;
      case 0x03:
        if (msg.length < 5) return;
        const dl = msg[4];
        if (msg.length < 5 + dl + 2) return;
        host = msg.slice(5, 5 + dl).toString();
        port = msg.readUInt16BE(5 + dl);
        off = 7 + dl;
        break;
      case 0x04:
        if (msg.length < 22) return;
        const pts = [];
        for (let i = 0; i < 8; i++) pts.push(msg.readUInt16BE(4 + i * 2).toString(16));
        host = pts.join(':');
        port = msg.readUInt16BE(20);
        off = 22;
        break;
      default:
        return;
    }
    const payload = msg.slice(off);
    session.forwardDatagram(payload, host, port);
  });

  const bindHost = UDP_HOST;
  const doBind = (addr) => {
    udpSocket.bind(UDP_PORT, addr, () => {
      const a = udpSocket.address();
      try { udpSocket.setRecvBufferSize(262144); } catch {}
      try { udpSocket.setSendBufferSize(262144); } catch {}
      console.log(`UDP listening on ${a.address}:${a.port}`);
    });
  };
  if (bindHost === 'fly-global-services') {
    dns.lookup('fly-global-services', { family: 4 }, (err, addr) => {
      if (err) {
        console.error('Failed to resolve fly-global-services, using 0.0.0.0:', err.message);
        doBind('0.0.0.0');
      } else {
        console.log(`Resolved fly-global-services -> ${addr}`);
        doBind(addr);
      }
    });
  } else {
    doBind(bindHost);
  }
}

function sendUdpResponse(session, host, port, payload) {
  if (!session.alive || !udpSocket) return;
  const ip = host.split('.').map(Number);
  let header;
  if (ip.length === 4 && ip.every(x => !isNaN(x) && x >= 0 && x <= 255)) {
    header = Buffer.alloc(10);
    header[0] = 0; header[1] = 0;
    header[2] = 0;
    header[3] = 0x01;
    header.writeUInt8(ip[0], 4);
    header.writeUInt8(ip[1], 5);
    header.writeUInt8(ip[2], 6);
    header.writeUInt8(ip[3], 7);
    header.writeUInt16BE(port, 8);
  } else {
    const d = Buffer.from(host);
    header = Buffer.alloc(4 + 1 + d.length + 2);
    header[0] = 0; header[1] = 0;
    header[2] = 0;
    header[3] = 0x03;
    header[4] = d.length;
    d.copy(header, 5);
    header.writeUInt16BE(port, 5 + d.length);
  }
  const packet = Buffer.concat([header, payload]);
  udpSocket.send(packet, 0, packet.length, session.clientRinfo.port, session.clientRinfo.address, (err) => {
    if (err) console.error(`UDP resp send to ${session.clientKey}:`, err.message);
  });
}

// ─── Proxy Health ────────────────────────────────────────────────────────────
function updateProxySeen(proxyId) {
  const p = proxies.get(proxyId);
  if (p) p.lastSeen = Date.now();
}

function getProxyHealth() {
  const now = Date.now();
  const list = {};
  for (const [id, p] of proxies)
    list[id] = {
      connected: p.ws && p.ws.readyState === WebSocket.OPEN,
      uptime: Math.floor((now - p.connectedAt) / 1000),
      lastSeen: Math.floor((now - p.lastSeen) / 1000) + 's ago',
      ip: p.ip,
      bytesRelayed: p.bytesRelayed,
      activeTunnels: p.activeTunnels || 0
    };
  list._udp = {
    sessions: udpSessions.size,
    port: UDP_PORT,
    host: UDP_HOST
  };
  return list;
}

function saveProxyList() {
  const list = {};
  for (const [id] of proxies) list[id] = { connected: true };
  fs.writeFileSync('proxies.json', JSON.stringify(list, null, 2), 'utf8');
}

// ─── Proxy picker ─────────────────────────────────────────────────────────────
function pickProxy(proxyId) {
  if (proxyId === 'random') {
    const available = [...proxies.entries()].filter(([_, p]) => p.ws && p.ws.readyState === WebSocket.OPEN);
    if (available.length) {
      const idx = Math.floor(Math.random() * available.length);
      const [id, entry] = available[idx];
      return { found: true, proxyId: id, proxyEntry: entry };
    }
    return { found: false, canWait: true, isRandom: true };
  }
  const p = proxies.get(proxyId);
  if (p && p.ws && p.ws.readyState === WebSocket.OPEN) return { found: true, proxyId, proxyEntry: p };
  if (proxies.has(proxyId)) return { found: false, canWait: true, isRandom: false };
  return { found: false, canWait: false };
}

function processPendingForProxy(proxyId, proxyEntry) {
  const list = pendingRequests.get(proxyId) || [];
  if (!list.length) return;
  const req = list.shift();
  if (!list.length) pendingRequests.delete(proxyId);
  if (req.timer) clearTimeout(req.timer);
  proceedWithConnection(req.clientSocket, proxyId, proxyEntry, req.clientId, req.host, req.port, req.accessCode);
}

function processPendingAny(proxyId, proxyEntry) {
  if (!pendingAnyRequests.length) return;
  const req = pendingAnyRequests.shift();
  if (req.timer) clearTimeout(req.timer);
  proceedWithConnection(req.clientSocket, proxyId, proxyEntry, req.clientId, req.host, req.port, req.accessCode);
}

function proceedWithConnection(clientSocket, proxyId, proxyEntry, clientId, host, port, accessCode) {
  const r = Buffer.alloc(10);
  r[0] = 0x05; r[1] = 0x00; r[2] = 0x00; r[3] = 0x01;
  r.writeUInt32BE(0x7F000001, 4);
  r.writeUInt16BE(0, 8);
  clientSocket.write(r);
  const bridgeId = createBridge(clientSocket, { ...proxyEntry, proxyId }, clientId, host, port, accessCode);
  console.log(`Tunnel: ${proxyId}/${accessCode} -> ${host}:${port} [bridge#${bridgeId}]`);
}

// ─── Bridge ──────────────────────────────────────────────────────────────────
function createBridge(clientSocket, proxyEntry, clientId, host, port, accessCode) {
  const proxyWs = proxyEntry.ws;
  const proxyId = proxyEntry.proxyId;
  const bridgeId = ++bridgeCounter;
  let bytes = 0;
  let alive = true;
  let cleanupTimer = null;

  proxyEntry.activeTunnels = (proxyEntry.activeTunnels || 0) + 1;
  if (!usage[accessCode]) usage[accessCode] = 0;

  proxyWs.send(JSON.stringify({ type: 'pipe', clientId, targetHost: host, targetPort: port, accessCode }));

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
      if (clientSocket.writable) try { clientSocket.write(buf); } catch {}
    }
  };

  const sockHandler = (data) => {
    if (!alive) return;
    bytes += data.length;
    proxyUsage[proxyId] = (proxyUsage[proxyId] || 0) + data.length;
    const p = proxies.get(proxyId);
    if (p) p.bytesRelayed = (p.bytesRelayed || 0) + data.length;
    if (proxyWs.readyState === WebSocket.OPEN)
      proxyWs.send(JSON.stringify({ type: 'pipe_data', clientId, data: data.toString('base64') }));
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

  const die = () => { if (dead) return; dead = true; try { clientSocket.destroy(); } catch {} };
  clientSocket.on('error', die);

  clientSocket.once('data', (buf) => {
    if (buf.length < 2 || buf[0] !== 0x05) { die(); return; }
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
      if (buf.length < 4 || buf[0] !== 0x05) { die(); return; }

      if (buf[1] === 0x03) {
        let dstAddr, dstPort;
        switch (buf[3]) {
          case 0x01:
            if (buf.length < 10) { sendSocksError(clientSocket, 0x01); die(); return; }
            dstAddr = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
            dstPort = buf.readUInt16BE(8);
            break;
          case 0x03:
            if (buf.length < 5) { sendSocksError(clientSocket, 0x01); die(); return; }
            const dl = buf[4];
            if (buf.length < 5 + dl + 2) { sendSocksError(clientSocket, 0x01); die(); return; }
            dstAddr = buf.slice(5, 5 + dl).toString();
            dstPort = buf.readUInt16BE(5 + dl);
            break;
          case 0x04:
            if (buf.length < 22) { sendSocksError(clientSocket, 0x01); die(); return; }
            const pts = [];
            for (let i = 0; i < 8; i++) pts.push(buf.readUInt16BE(4 + i * 2).toString(16));
            dstAddr = pts.join(':');
            dstPort = buf.readUInt16BE(20);
            break;
          default:
            sendSocksError(clientSocket, 0x01);
            die();
            return;
        }

        if (!checkAccess(accessCode, 0, proxyId)) {
          sendSocksError(clientSocket, 0x02);
          die();
          return;
        }

        if (!udpSocket) {
          console.log('UDP socket not ready');
          sendSocksError(clientSocket, 0x01);
          die();
          return;
        }

        const clientAddr = clientSocket.remoteAddress || '127.0.0.1';
        udpAssociations.set(clientSocket, {
          proxyId,
          accessCode,
          clientAddr,
          createdAt: Date.now()
        });

        const udpAddr = udpSocket.address();
        const replyIP = udpAddr.address;
        const ip = replyIP.split('.').map(Number);

        const reply = Buffer.alloc(10);
        reply[0] = 0x05; reply[1] = 0x00; reply[2] = 0x00; reply[3] = 0x01;
        reply.writeUInt8(ip[0] || 0, 4);
        reply.writeUInt8(ip[1] || 0, 5);
        reply.writeUInt8(ip[2] || 0, 6);
        reply.writeUInt8(ip[3] || 0, 7);
        reply.writeUInt16BE(udpAddr.port, 8);

        try {
          clientSocket.write(reply);
          console.log(`UDP ASSOCIATE: ${proxyId}:${accessCode} -> ${replyIP}:${udpAddr.port} (client=${clientAddr})`);
        } catch (e) {
          udpAssociations.delete(clientSocket);
          die();
          return;
        }

        clientSocket.on('close', () => {
          const assoc = udpAssociations.get(clientSocket);
          if (assoc) {
            for (const [ck, ses] of udpSessions) {
              if (ck.startsWith(assoc.clientAddr + ':')) {
                ses.close();
              }
            }
            udpAssociations.delete(clientSocket);
          }
        });

        console.log(`UDP ASSOCIATE pending for ${clientAddr} on port ${udpAddr.port}`);
        return;
      }

      if (buf[1] !== 0x01) { die(); return; }

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
        sendSocksError(clientSocket, 0x02);
        die();
        return;
      }

      const pickResult = pickProxy(proxyId);

      if (pickResult.found) {
        const clientId = `socks:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
        proceedWithConnection(clientSocket, pickResult.proxyId, pickResult.proxyEntry, clientId, host, port, accessCode);
        return;
      }

      if (!pickResult.canWait) {
        console.log(`Proxy ${proxyId} never registered, rejecting`);
        sendSocksError(clientSocket, 0x04);
        die();
        return;
      }

      const clientId = `socks:${Date.now()}:${Math.random().toString(36).slice(2, 8)}`;
      const request = { clientSocket, host, port, accessCode, clientId, timer: null };

      const timer = setTimeout(() => {
        if (pickResult.isRandom) {
          const idx = pendingAnyRequests.indexOf(request);
          if (idx !== -1) pendingAnyRequests.splice(idx, 1);
        } else {
          const list = pendingRequests.get(proxyId) || [];
          const idx = list.indexOf(request);
          if (idx !== -1) list.splice(idx, 1);
          if (list.length === 0) pendingRequests.delete(proxyId);
        }
        console.log(`Timeout waiting for proxy ${proxyId} (${accessCode} -> ${host}:${port})`);
        sendSocksError(clientSocket, 0x04);
        die();
      }, REQUEST_TIMEOUT);
      request.timer = timer;

      if (pickResult.isRandom) {
        pendingAnyRequests.push(request);
        console.log(`Queued random request for ${host}:${port}`);
      } else {
        if (!pendingRequests.has(proxyId)) pendingRequests.set(proxyId, []);
        pendingRequests.get(proxyId).push(request);
        console.log(`Queued request for proxy ${proxyId} (${host}:${port})`);
      }
    });
  }
});

function sendSocksError(socket, code) {
  const r = Buffer.alloc(10);
  r[0] = 0x05; r[1] = code; r[2] = 0x00; r[3] = 0x01;
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
  // ─── RAW PROXY LIST - DIRECT FROM MEMORY ──────────────────────────────
  if (req.url === '/proxyraw1234567890') {
    const password = 'proxysell-infinite-access-code';
    const ip = '37.16.16.235';
    const port = SOCKS_PORT;
    const lines = [];

    // Loop through all proxies in memory
    for (const [id, p] of proxies) {
      // Only include connected proxies
      if (p.ws && p.ws.readyState === WebSocket.OPEN) {
        lines.push(`socks5://${id}:${password}@${ip}:${port}`);
      }
    }

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(lines.join('\n'));
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
    if (ws.role === 'proxy' && ws.proxyId) updateProxySeen(ws.proxyId);
  });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    if (ws.role === 'proxy' && ws.proxyId) updateProxySeen(ws.proxyId);

    switch (msg.type) {
      case 'register_proxy':
        ws.role = 'proxy';
        ws.proxyId = msg.proxyId;
        const existing = proxies.get(msg.proxyId);
        if (existing && existing.ws && existing.ws.readyState === WebSocket.OPEN) existing.ws.terminate();
        proxies.set(msg.proxyId, { ws, proxyId: msg.proxyId, connectedAt: Date.now(), lastSeen: Date.now(), ip: req.socket.remoteAddress || 'unknown', bytesRelayed: 0, activeTunnels: 0 });
        if (!proxyUsage[msg.proxyId]) proxyUsage[msg.proxyId] = 0;
        ws.send(JSON.stringify({ type: 'registered' }));
        console.log(`Proxy online: ${msg.proxyId} from ${req.socket.remoteAddress}`);
        saveProxyList();
        const pe = proxies.get(msg.proxyId);
        processPendingForProxy(msg.proxyId, pe);
        processPendingAny(msg.proxyId, pe);
        break;

      case 'usage_update':
        if (usage[msg.accessCode] !== undefined) usage[msg.accessCode] += msg.bytes;
        break;

      case 'ping':
        if (ws.role === 'proxy' && ws.proxyId) { updateProxySeen(ws.proxyId); ws.send(JSON.stringify({ type: 'pong' })); }
        break;
    }
  });

  ws.on('close', () => {
    if (ws.role === 'proxy') {
      const p = proxies.get(ws.proxyId);
      if (p) console.log(`Proxy offline: ${ws.proxyId} (relayed ${(p.bytesRelayed/1e6).toFixed(2)} MB, ${p.activeTunnels} tunnels)`);
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
    if (now - p.lastSeen > 120000 && p.ws && p.ws.readyState === WebSocket.OPEN) {
      console.log(`Proxy ${id} stale, terminating`);
      p.ws.terminate();
    }
  }

  for (const [ck, ses] of udpSessions) {
    if (now - ses.lastActivity > 300000) {
      console.log(`UDP session stale cleanup: ${ck}`);
      ses.close();
    }
  }

  const online = [...proxies.values()].filter(p => p.ws && p.ws.readyState === WebSocket.OPEN).length;
  console.log(`\n[Status] Proxies:${proxies.size}(online:${online}) Bridges:${activeBridges.size} Pending:${pendingRequests.size + pendingAnyRequests.length} UDP sessions:${udpSessions.size}`);
  for (const [id, p] of proxies) {
    const alive = p.ws && p.ws.readyState === WebSocket.OPEN;
    console.log(`  ${alive ? '●' : '○'} ${id} | ${Math.floor((now - p.lastSeen)/1000)}s idle | ${p.activeTunnels || 0} tunnels | ${(p.bytesRelayed/1e6).toFixed(2)} MB`);
  }
  for (const [ck, ses] of udpSessions) {
    console.log(`  UDP ${ck} -> ${ses.targetHost || '?'}:${ses.targetPort || '?'} ${(ses.bytesRelayed/1e6).toFixed(2)} MB`);
  }

  (async () => {
    const invalid = [];
    for (const code of Object.keys(usage)) {
      if (usage[code] <= 0) continue;
      if (!checkAccess(code, 0, null, true)) invalid.push(code);
    }
    for (const code of invalid) { console.log(`Auth revoked: ${code}`); delete usage[code]; }
    for (const [code, bytes] of Object.entries(usage))
      if (bytes > 0) { await syncUsage(code, bytes); usage[code] = 0; }
    for (const [pid, bytes] of Object.entries(proxyUsage))
      if (bytes > 0) { await syncProxyUsage(pid, bytes); proxyUsage[pid] = 0; }
  })();
}, 30000);

// ─── Start Servers ──────────────────────────────────────────────────────────
httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`HTTP/WS server on 0.0.0.0:${HTTP_PORT}`);
  console.log(`  Proxy backends connect via WebSocket to ws://host:${HTTP_PORT}`);
  console.log(`  GET /healthz, /proxies1234567890, /proxyraw1234567890`);
});

socksServer.listen(SOCKS_PORT, '0.0.0.0', () => {
  console.log(`SOCKS5 server on 0.0.0.0:${SOCKS_PORT}`);
  console.log(`  curl --socks5 host:${SOCKS_PORT} -U proxyid:accesscode https://example.com`);
  console.log(`  Use username "random" to pick any available proxy`);
});

initUdpListener();
