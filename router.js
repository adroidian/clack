#!/usr/bin/env node
/**
 * Clack Router
 *
 * Generic sanitized router for inter-agent message delivery.
 *
 * Endpoints:
 *   GET  /health
 *   POST /route      { to, from, topic, message }
 *   GET  /poll/:agent
 *   POST /queue/:agent
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');

const { WebSocket } = (() => {
  const paths = ['ws'];
  for (const p of paths) {
    try { return require(p); } catch {}
  }
  throw new Error('ws module not found');
})();

const CONFIG_PATH = process.env.CLACK_CONFIG_PATH || path.join(__dirname, 'config.json');
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const {
  agent,
  port,
  clackToken,
  gateway: defaultGateway,
  gateways: extraGateways = {},
  routes = {}
} = config;

const gatewayMap = { local: defaultGateway, ...extraGateways };
const gwPool = {};
const pendingPoll = {};
const startTime = Date.now();

function getOrCreateGw(name) {
  if (!gwPool[name]) {
    gwPool[name] = { socket: null, ready: false, pending: new Map() };
    connectGateway(name);
  }
  return gwPool[name];
}

function connectGateway(name) {
  const cfg = gatewayMap[name];
  if (!cfg) {
    console.error(`[clack-router] unknown gateway: ${name}`);
    return;
  }

  const ws = new WebSocket(cfg.url);
  const gw = gwPool[name];
  gw.socket = ws;
  gw.ready = false;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'event' && msg.event === 'connect.challenge') {
      ws.send(JSON.stringify({
        type: 'req',
        id: randomUUID(),
        method: 'connect',
        params: {
          client: {
            id: 'clack-router',
            mode: 'cli',
            version: '1.0.0',
            platform: 'node',
            displayName: `clack-router[${agent}/${name}]`
          },
          auth: { token: cfg.token },
          scopes: ['operator.write'],
          minProtocol: 3,
          maxProtocol: 3
        }
      }));
      return;
    }

    if (msg.type === 'res' && msg.ok === true && !gw.ready) {
      gw.ready = true;
      return;
    }

    if (msg.type === 'res' && msg.id) {
      const cb = gw.pending.get(msg.id);
      if (!cb) return;
      clearTimeout(cb.timer);
      gw.pending.delete(msg.id);
      if (msg.ok) cb.resolve(msg.result);
      else cb.reject(new Error(msg.error?.message || 'gateway error'));
    }
  });

  ws.on('error', () => {
    gw.ready = false;
  });

  ws.on('close', () => {
    gw.ready = false;
    gw.socket = null;
    setTimeout(() => connectGateway(name), 5000);
  });
}

function gwSend(gwName, method, params) {
  return new Promise((resolve, reject) => {
    const gw = getOrCreateGw(gwName);
    if (!gw.ready || !gw.socket) {
      reject(new Error(`gateway [${gwName}] not connected`));
      return;
    }
    const id = randomUUID();
    const timer = setTimeout(() => {
      gw.pending.delete(id);
      reject(new Error(`gateway [${gwName}] timeout: ${method}`));
    }, 10000);
    gw.pending.set(id, { resolve, reject, timer });
    gw.socket.send(JSON.stringify({ type: 'req', id, method, params }));
  });
}

async function routeMessage({ to, from, topic, message }) {
  const route = routes[to];
  if (!route) throw new Error(`unknown agent: ${to}`);

  const envelope = `[clack:${from}→${to}][${topic}] ${message}`;

  if (typeof route.gateway === 'string' && gatewayMap[route.gateway]) {
    try {
      await gwSend(route.gateway, 'chat.send', {
        sessionKey: route.sessionKey,
        message: envelope,
        idempotencyKey: `clack-${randomUUID()}`
      });
      return { ok: true, delivery: 'gateway', gateway: route.gateway };
    } catch (err) {
      if (!pendingPoll[to]) pendingPoll[to] = [];
      pendingPoll[to].push({ from, topic, message, ts: Date.now() });
      return { ok: true, delivery: 'queued', via: 'poll', queued: pendingPoll[to].length };
    }
  }

  const remoteUrl = `${route.gateway}/route`;
  const body = JSON.stringify({ to, from, topic, message });
  await httpPost(remoteUrl, body, clackToken);
  return { ok: true, delivery: 'remote', via: route.gateway };
}

function httpPost(url, body, token) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const client = u.protocol === 'https:' ? require('https') : require('http');
    const req = client.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'X-Clack-Token': token
      }
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(data)); }
          catch { resolve({ ok: true, raw: data }); }
        } else {
          reject(new Error(`remote router ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('remote router timeout'));
    });
    req.write(body);
    req.end();
  });
}

const server = http.createServer((req, res) => {
  const respond = (status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  if (req.method === 'GET' && req.url === '/health') {
    const gateways = {};
    for (const [name, gw] of Object.entries(gwPool)) gateways[name] = gw.ready;
    return respond(200, {
      ok: true,
      agent,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      gateways
    });
  }

  if (req.method === 'POST' && req.url === '/route') {
    if (req.headers['x-clack-token'] !== clackToken) {
      return respond(401, { ok: false, error: 'unauthorized' });
    }
    let body = '';
    req.on('data', d => body += d);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);
        const { to, from, topic = 'message', message } = payload;
        if (!to || !from || !message) {
          return respond(400, { ok: false, error: 'missing required fields: to, from, message' });
        }
        const result = await routeMessage({ to, from, topic, message });
        respond(200, result);
      } catch (err) {
        respond(500, { ok: false, error: err.message });
      }
    });
    return;
  }

  const pollMatch = req.method === 'GET' && req.url.match(/^\/poll\/([^/]+)$/);
  if (pollMatch) {
    const agentName = pollMatch[1];
    const messages = pendingPoll[agentName] || [];
    delete pendingPoll[agentName];
    return respond(200, { ok: true, agent: agentName, messages, count: messages.length });
  }

  const queueMatch = req.method === 'POST' && req.url.match(/^\/queue\/([^/]+)$/);
  if (queueMatch) {
    const agentName = queueMatch[1];
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const { from, topic, message } = JSON.parse(body);
        if (!pendingPoll[agentName]) pendingPoll[agentName] = [];
        pendingPoll[agentName].push({ from, topic, message, ts: Date.now() });
        respond(200, { ok: true, delivery: 'queued', via: 'poll', queued: pendingPoll[agentName].length });
      } catch (err) {
        respond(400, { ok: false, error: err.message });
      }
    });
    return;
  }

  respond(404, { ok: false, error: 'not found' });
});

for (const name of Object.keys(gatewayMap)) getOrCreateGw(name);
server.listen(port, '0.0.0.0', () => {
  console.log(`[clack-router] ${agent} listening on :${port}`);
});
