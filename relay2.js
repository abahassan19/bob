// relay-tcp.js
const net = require('net');
const fs = require('fs');
const dns = require('dns');

// ─── CONFIG ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 10000;
const PIPE_TIMEOUT = 300000;
const AUTH_ENABLED = true;

let checkAccess, syncUsage, syncProxyUsage;

if (AUTH_ENABLED) {
  const auth = require('./auth');
  checkAccess = auth.checkAccess;
  syncUsage = auth.syncUsage;
  syncProxyUsage = auth.syncProxyUsage;
} else {
  checkAccess = () => true;
  syncUsage = async () => {};
  syncProxyUsage = async () => {};
}

// ─── State ───────────────────────────────────────────────────────────────────
const proxySockets = new Map();
const proxyPool = new Set();
const proxyReadBuffers = new Map();
const usage = {};
const proxyUsage = {};
const activeTunnels = new Map();
const pendingPipeHandlers = new Map();

process.on('uncaughtException', (err) => console.error('Uncaught:', err.message));
process.on('unhandledRejection', (reason) => console.error('Unhandled Rejection:', reason.message));

function saveProxyList() {
  const list = {};
  for (const id of proxyPool) list[id] = { connected: true };
  fs.writeFileSync('proxies.json', JSON.stringify(list, null, 2), 'utf8');
}

function findFallbackProxy(deadProxyId) {
  if (proxyPool.size === 0) return null;
  const candidates = [...proxyPool].filter(id => id !== deadProxyId);
  if (candidates.length === 0) return null;
  return candidates[Math.floor(Math.random() * candidates.length)];
}

function sendJsonMessage(socket, msg) {
  if (!socket || socket.destroyed) return;
  const json = JSON.stringify(msg);
  const buf = Buffer.from(json, 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(buf.length, 0);
  try { socket.write(Buffer.concat([header, buf])); } catch (e) {}
}

function parseMessages(data, buffer) {
  buffer = Buffer.concat([buffer, data]);
  const messages = [];
  while (buffer.length >= 4) {
    const msgLen = buffer.readUInt32BE(0);
    const totalLen = 4 + msgLen;
    if (msgLen === 0) { buffer = buffer.slice(4); continue; }
    if (buffer.length < totalLen) break;
    const json = buffer.toString('utf8', 4, totalLen);
    try { messages.push(JSON.parse(json)); } catch (e) {}
    buffer = buffer.slice(totalLen);
  }
  return { messages, buffer };
}

// ─── Server ──────────────────────────────────────────────────────────────────
const server = net.createServer((socket) => {
  socket.on('error', () => {});
  socket.setTimeout(30000, () => socket.end());

  socket.once('data', (firstData) => {
    if (firstData[0] === 0x05) {
      handleSocks5(socket, firstData);
    } else {
      handleProxyConnection(socket, firstData);
    }
  });

  // ─── SOCKS5 Handler ────────────────────────────────────────────────────
  function handleSocks5(clientSocket, initialData) {
    let buf = initialData;
    let state = 0; // 0=greeting, 1=auth, 2=request
    let proxyIdForTunnel = null;
    let accessCodeForTunnel = AUTH_ENABLED ? null : 'no-auth';
    let targetHost = null;
    let targetPort = null;
    let clientId = null;
    let actualProxyId = null;
    let pipeEstablished = false;
    let bytes = 0;
    let alive = false;
    let cleanupTimer = null;
    let cleanupDone = false;

    const doCleanup = () => {
      if (cleanupDone) return;
      cleanupDone = true;
      alive = false;
      if (cleanupTimer) clearTimeout(cleanupTimer);
      if (accessCodeForTunnel && bytes > 0) {
        usage[accessCodeForTunnel] = (usage[accessCodeForTunnel] || 0) + bytes;
      }
      if (actualProxyId && bytes > 0) {
        proxyUsage[actualProxyId] = (proxyUsage[actualProxyId] || 0) + bytes;
      }
      activeTunnels.delete(clientSocket);
      if (clientId) pendingPipeHandlers.delete(clientId);
      try { clientSocket.end(); } catch {}
    };

    function processBuffer() {
      // ── SOCKS5 Greeting ──
      if (state === 0 && buf.length >= 2) {
        const numMethods = buf[1];
        const totalLen = 2 + numMethods;
        if (buf.length < totalLen) return;

        const methods = buf.slice(2, totalLen);

        if (AUTH_ENABLED) {
          if (!methods.includes(0x02)) {
            clientSocket.write(Buffer.from([0x05, 0xFF]));
            clientSocket.end();
            return;
          }
          clientSocket.write(Buffer.from([0x05, 0x02]));
          state = 1;
        } else {
          if (!methods.includes(0x00)) {
            clientSocket.write(Buffer.from([0x05, 0xFF]));
            clientSocket.end();
            return;
          }
          clientSocket.write(Buffer.from([0x05, 0x00]));
          state = 2; // skip auth
        }

        buf = buf.slice(totalLen);
        processBuffer();
        return;
      }

      // ── SOCKS5 Auth (AUTH_ENABLED only) ──
      if (AUTH_ENABLED && state === 1 && buf.length >= 2) {
        const unameLen = buf[1];
        if (buf.length < 3 + unameLen) return;
        const passLen = buf[2 + unameLen];
        const totalLen = 3 + unameLen + passLen;
        if (buf.length < totalLen) return;

        const username = buf.toString('utf8', 2, 2 + unameLen);
        const password = buf.toString('utf8', 3 + unameLen, 3 + unameLen + passLen);

        proxyIdForTunnel = username;
        accessCodeForTunnel = password;

        if (proxyPool.size === 0) {
          clientSocket.write(Buffer.from([0x01, 0x01]));
          clientSocket.end();
          return;
        }

        if (!proxyPool.has(proxyIdForTunnel)) {
          console.log(`SOCKS5 auth denied: proxy ${proxyIdForTunnel} not online`);
          clientSocket.write(Buffer.from([0x01, 0x01]));
          clientSocket.end();
          return;
        }

        if (!checkAccess(accessCodeForTunnel)) {
          console.log(`SOCKS5 auth denied: bad access code`);
          clientSocket.write(Buffer.from([0x01, 0x01]));
          clientSocket.end();
          return;
        }

        clientSocket.write(Buffer.from([0x01, 0x00]));
        buf = buf.slice(totalLen);
        state = 2;
        processBuffer();
        return;
      }

      // ── SOCKS5 Request ──
      if (state === 2 && buf.length >= 10) {
        if (buf[0] !== 0x05 || buf[1] !== 0x01) {
          clientSocket.write(Buffer.from([0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
          clientSocket.end();
          return;
        }

        if (proxyPool.size === 0) {
          console.log('SOCKS5 request denied: no proxies online');
          clientSocket.write(Buffer.from([0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
          clientSocket.end();
          return;
        }

        const addrType = buf[3];
        let addrLen;

        if (addrType === 0x01) addrLen = 10;
        else if (addrType === 0x03) addrLen = 5 + buf[4] + 2;
        else if (addrType === 0x04) addrLen = 22;
        else {
          clientSocket.write(Buffer.from([0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
          clientSocket.end();
          return;
        }

        if (buf.length < addrLen) return;

        if (addrType === 0x01) {
          targetHost = `${buf[4]}.${buf[5]}.${buf[6]}.${buf[7]}`;
          targetPort = buf.readUInt16BE(8);
        } else if (addrType === 0x03) {
          const dLen = buf[4];
          targetHost = buf.toString('utf8', 5, 5 + dLen);
          targetPort = buf.readUInt16BE(5 + dLen);
        } else {
          const parts = [];
          for (let i = 0; i < 8; i++) parts.push(buf.readUInt16BE(4 + i * 2).toString(16));
          targetHost = parts.join(':');
          targetPort = buf.readUInt16BE(20);
        }

        buf = buf.slice(addrLen);

        // Pick a proxy
        if (AUTH_ENABLED) {
          actualProxyId = proxyIdForTunnel;
        } else {
          // Pick a random online proxy
          const picks = [...proxyPool];
          actualProxyId = picks[Math.floor(Math.random() * picks.length)];
        }
        proxyIdForTunnel = actualProxyId;

        const resolveAndConnect = (resolvedHost) => {
          let proxySocket = proxySockets.get(actualProxyId);

          if (!proxySocket || proxySocket.destroyed) {
            const fb = findFallbackProxy(actualProxyId);
            if (!fb || !proxySockets.has(fb) || proxySockets.get(fb).destroyed) {
              console.log(`SOCKS5: proxy ${actualProxyId} gone, no fallback`);
              clientSocket.write(Buffer.from([0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
              clientSocket.end();
              return;
            }
            actualProxyId = fb;
            proxySocket = proxySockets.get(fb);
            console.log(`Fallback at connect: ${proxyIdForTunnel} → ${fb}`);
          }

          clientId = `${clientSocket.remoteAddress}:${clientSocket.remotePort}-${Date.now()}-${Math.random().toString(36).slice(2,6)}`;

          console.log(`SOCKS5: piping ${actualProxyId} -> ${resolvedHost}:${targetPort} [${clientId}]`);

          sendJsonMessage(proxySocket, {
            type: 'pipe',
            clientId: clientId,
            targetHost: resolvedHost,
            targetPort: targetPort,
            accessCode: accessCodeForTunnel || 'no-auth'
          });

          // Give proxy time to establish TCP to target
          setTimeout(() => {
            if (clientSocket.destroyed) {
              console.log(`SOCKS5: client socket destroyed before pipe established`);
              return;
            }

            // Send SOCKS5 success
            const bndAddr = Buffer.alloc(4, 0);
            const bndPort = Buffer.alloc(2, 0);
            clientSocket.write(Buffer.concat([
              Buffer.from([0x05, 0x00, 0x00, 0x01]),
              bndAddr,
              bndPort
            ]));

            alive = true;
            pipeEstablished = true;

            activeTunnels.set(clientSocket, {
              originalProxyId: proxyIdForTunnel,
              proxyId: actualProxyId,
              clientId: clientId,
              targetHost: resolvedHost,
              targetPort: targetPort,
              accessCode: accessCodeForTunnel || 'no-auth',
              alive: true
            });

            if (!usage[accessCodeForTunnel || 'no-auth']) usage[accessCodeForTunnel || 'no-auth'] = 0;
            if (!proxyUsage[actualProxyId]) proxyUsage[actualProxyId] = 0;

            const proxyMsgHandler = (incomingMsg) => {
              if (!alive) return;
              if (incomingMsg.type === 'pipe_data' && incomingMsg.clientId === clientId) {
                const raw = Buffer.from(incomingMsg.data, 'base64');
                bytes += raw.length;
                proxyUsage[actualProxyId] = (proxyUsage[actualProxyId] || 0) + raw.length;
                try { clientSocket.write(raw); } catch (e) {}
              }
            };

            pendingPipeHandlers.set(clientId, proxyMsgHandler);

            const clientDataHandler = (data) => {
              if (!alive) return;
              bytes += data.length;
              proxyUsage[actualProxyId] = (proxyUsage[actualProxyId] || 0) + data.length;
              const pSocket = proxySockets.get(actualProxyId);
              if (pSocket && !pSocket.destroyed) {
                sendJsonMessage(pSocket, {
                  type: 'pipe_data',
                  clientId: clientId,
                  data: data.toString('base64')
                });
              }
            };

            const onProxyDead = () => {
              if (!alive) return;
              const tunnel = activeTunnels.get(clientSocket);
              if (!tunnel) { doCleanup(); return; }

              const fbId = findFallbackProxy(tunnel.proxyId);
              if (!fbId) { doCleanup(); return; }

              const fbSocket = proxySockets.get(fbId);
              if (!fbSocket || fbSocket.destroyed) { doCleanup(); return; }

              console.log(`Mid-connection failover: ${tunnel.proxyId} → ${fbId}`);

              if (clientId) pendingPipeHandlers.delete(clientId);

              tunnel.proxyId = fbId;
              actualProxyId = fbId;
              activeTunnels.set(clientSocket, tunnel);
              pendingPipeHandlers.set(clientId, proxyMsgHandler);

              sendJsonMessage(fbSocket, {
                type: 'pipe',
                clientId: clientId,
                targetHost: resolvedHost,
                targetPort: targetPort,
                accessCode: accessCodeForTunnel || 'no-auth'
              });
            };

            clientSocket.on('data', clientDataHandler);
            clientSocket.on('close', doCleanup);
            clientSocket.on('error', doCleanup);

            cleanupTimer = setTimeout(doCleanup, PIPE_TIMEOUT);
          }, 2000);
        };

        if (addrType === 0x03) {
          dns.lookup(targetHost, { family: 4 }, (err, address) => {
            if (err) {
              console.log(`SOCKS5: DNS lookup failed for ${targetHost}: ${err.message}`);
              clientSocket.write(Buffer.from([0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
              clientSocket.end();
              return;
            }
            resolveAndConnect(address);
          });
        } else {
          resolveAndConnect(targetHost);
        }
      }
    }

    clientSocket.on('data', (data) => {
      if (pipeEstablished) return; // after pipe established, data handler is separate
      buf = Buffer.concat([buf, data]);
      processBuffer();
    });

    clientSocket.on('close', () => {
      if (!pipeEstablished) return;
      doCleanup();
    });

    // Process initial data
    processBuffer();
  }

  // ─── Proxy Backend Handler ──────────────────────────────────────────────
  function handleProxyConnection(proxySocket, initialData) {
    let readBuf = initialData;
    let registeredProxyId = null;

    proxySocket.on('data', (data) => {
      const { messages, buffer } = parseMessages(data, readBuf);
      readBuf = buffer;

      for (const msg of messages) {
        if (msg.type === 'register_proxy') {
          registeredProxyId = msg.proxyId;
          proxySockets.set(registeredProxyId, proxySocket);
          proxyPool.add(registeredProxyId);
          proxyReadBuffers.set(registeredProxyId, Buffer.alloc(0));
          if (!proxyUsage[registeredProxyId]) proxyUsage[registeredProxyId] = 0;
          sendJsonMessage(proxySocket, { type: 'registered' });
          console.log(`Proxy online via TCP: ${registeredProxyId}`);
          saveProxyList();

        } else if (msg.type === 'pipe_data') {
          const handler = pendingPipeHandlers.get(msg.clientId);
          if (handler) {
            handler(msg);
          } else {
            console.log(`No handler for pipe_data clientId=${msg.clientId}`);
          }
        } else if (msg.type === 'usage_update') {
          if (usage[msg.accessCode] !== undefined) usage[msg.accessCode] += msg.bytes;
        }
      }
    });

    proxySocket.on('close', () => {
      if (registeredProxyId) {
        proxySockets.delete(registeredProxyId);
        proxyPool.delete(registeredProxyId);
        proxyReadBuffers.delete(registeredProxyId);
        console.log(`Proxy offline: ${registeredProxyId}`);
        delete proxyUsage[registeredProxyId];
        saveProxyList();
      }
    });
  }
});

// ─── Periodic Usage Sync ─────────────────────────────────────────────────────
setInterval(async () => {
  if (AUTH_ENABLED) {
    const invalid = [];
    for (const code of Object.keys(usage)) {
      if (usage[code] <= 0) continue;
      if (!checkAccess(code)) invalid.push(code);
    }
    for (const code of invalid) delete usage[code];

    for (const [code, bytes] of Object.entries(usage)) {
      if (bytes > 0) { await syncUsage(code, bytes); usage[code] = 0; }
    }
  }

  for (const [id, bytes] of Object.entries(proxyUsage)) {
    if (bytes > 0) {
      if (AUTH_ENABLED) await syncProxyUsage(id, bytes);
      proxyUsage[id] = 0;
    }
  }

  console.log(`\nProxies:${proxyPool.size}`);
  for (const [i, b] of Object.entries(proxyUsage)) if (b > 0) console.log(`  Proxy ${i}: ${(b/1e6).toFixed(2)} MB`);
}, 60000);

// ─── Start ───────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Relay listening on 0.0.0.0:${PORT}`);
  console.log(`Auth: ${AUTH_ENABLED ? 'ENABLED' : 'DISABLED'}`);
  console.log(`Proxies needed: at least 1 must be connected`);
});
