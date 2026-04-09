#!/usr/bin/env node
/**
 * Clack Router
 *
 * Core responsibilities:
 * - accept routed messages over HTTP
 * - look up the route for a target agent
 * - hand delivery off to a configured adapter
 * - queue poll fallback when an adapter cannot deliver
 *
 * Adapter responsibilities:
 * - speak a concrete local control protocol (for example ws-rpc)
 * - speak a concrete remote forwarding protocol (for example remote-http)
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');

const { WebSocket } = (() => {
  try { return require('ws'); } catch {}
  throw new Error('ws module not found');
})();

const CONFIG_PATH = process.env.CLACK_CONFIG_PATH || path.join(__dirname, 'config.json');
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
const {
  routerName = 'router',
  port = 7331,
  auth = {},
  adapters = {},
  routes = {}
} = config;

const sharedToken = auth.sharedToken || 'replace-me';
const adapterPools = {};
const pendingPoll = {};
const startTime = Date.now();

function getOrCreateAdapterState(name) {
  if (!adapterPools[name]) {
    adapterPools[name] = { socket: null, ready: false, pending: new Map() };
    const adapter = adapters[name];
    if (adapter?.type === 'ws-rpc') connectWsRpcAdapter(name, adapter);
  }
  return adapterPools[name];
}

function connectWsRpcAdapter(name, adapter) {
  const ws = new WebSocket(adapter.url);
  const state = adapterPools[name];
  state.socket = ws;
  state.ready = false;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    const connectCfg = adapter.connect || {};
    const deliverCfg = adapter.deliver || {};

    if (msg.type === 'event' && msg.event === (connectCfg.challengeEvent || 'connect.challenge')) {
      ws.send(JSON.stringify({
        type: 'req',
        id: randomUUID(),
        method: connectCfg.method || 'connect',
        params: {
          client: {
            id: 'clack-router',
            mode: 'cli',
            version: '1.0.0',
            platform: 'node',
            displayName: `clack-router[${routerName}/${name}]`
          },
          auth: { token: adapter.token },
          scopes: connectCfg.scopes || ['operator.write'],
          minProtocol: connectCfg.minProtocol || 3,
          maxProtocol: connectCfg.maxProtocol || 3
        }
      }));
      return;
    }

    if (msg.type === 'res' && msg.ok === true && !state.ready) {
      state.ready = true;
      return;
    }

    if (msg.type === 'res' && msg.id) {
      const cb = state.pending.get(msg.id);
      if (!cb) return;
      clearTimeout(cb.timer);
      state.pending.delete(msg.id);
      if (msg.ok) cb.resolve(msg.result);
      else cb.reject(new Error(msg.error?.message || `${deliverCfg.method || 'deliver'} failed`));
    }
  });

  ws.on('error', () => {
    state.ready = false;
  });

  ws.on('close', () => {
    state.ready = false;
    state.socket = null;
    setTimeout(() => connectWsRpcAdapter(name, adapter), adapter.reconnectMs || 5000);
  });
}

function wsRpcSend(adapterName, adapter, route, envelope) {
  return new Promise((resolve, reject) => {
    const state = getOrCreateAdapterState(adapterName);
    if (!state.ready || !state.socket) {
      reject(new Error(`adapter [${adapterName}] not connected`));
      return;
    }

    const deliverCfg = adapter.deliver || {};
    const id = randomUUID();
    const timer = setTimeout(() => {
      state.pending.delete(id);
      reject(new Error(`adapter [${adapterName}] timeout`));
    }, adapter.timeoutMs || 10000);

    const params = {
      [deliverCfg.targetField || 'target']: route.target,
      [deliverCfg.messageField || 'message']: envelope
    };
    if (deliverCfg.idempotencyField) {
      params[deliverCfg.idempotencyField] = `clack-${randomUUID()}`;
    }

    state.pending.set(id, { resolve, reject, timer });
    state.socket.send(JSON.stringify({
      type: 'req',
      id,
      method: deliverCfg.method || 'deliver',
      params
    }));
  });
}

function remoteHttpSend(adapter, routePayload) {
  return new Promise((resolve, reject) => {
    const u = new URL(adapter.baseUrl + (adapter.path || '/route'));
    const body = JSON.stringify(routePayload);
    const client = u.protocol === 'https:' ? https : http;
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body)
    };
    if (adapter.authHeader) headers[adapter.authHeader] = adapter.authToken || sharedToken;

    const req = client.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname,
      method: 'POST',
      headers
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(data)); }
          catch { resolve({ ok: true, raw: data }); }
        } else {
          reject(new Error(`remote endpoint ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(adapter.timeoutMs || 10000, () => {
      req.destroy();
      reject(new Error('remote endpoint timeout'));
    });
    req.write(body);
    req.end();
  });
}

async function deliverViaAdapter(adapterName, route, envelope, payload) {
  const adapter = adapters[adapterName];
  if (!adapter) throw new Error(`unknown adapter: ${adapterName}`);

  if (adapter.type === 'ws-rpc') {
    await wsRpcSend(adapterName, adapter, route, envelope);
    return { ok: true, delivery: 'local', adapter: adapterName };
  }

  if (adapter.type === 'remote-http') {
    await remoteHttpSend(adapter, payload);
    return { ok: true, delivery: 'remote', adapter: adapterName };
  }

  throw new Error(`unsupported adapter type: ${adapter.type}`);
}

async function routeMessage({ to, from, topic, message }) {
  const route = routes[to];
  if (!route) throw new Error(`unknown agent: ${to}`);

  const envelope = `[clack:${from}→${to}][${topic}] ${message}`;
  const payload = { to, from, topic, message };

  try {
    return await deliverViaAdapter(route.adapter, route, envelope, payload);
  } catch (err) {
    if (!pendingPoll[to]) pendingPoll[to] = [];
    pendingPoll[to].push({ from, topic, message, ts: Date.now() });
    return { ok: true, delivery: 'queued', via: 'poll', queued: pendingPoll[to].length, error: err.message };
  }
}

const server = http.createServer((req, res) => {
  const respond = (status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  if (req.method === 'GET' && req.url === '/health') {
    const adapterStatus = {};
    for (const [name, adapter] of Object.entries(adapters)) {
      if (adapter.type === 'ws-rpc') adapterStatus[name] = !!adapterPools[name]?.ready;
      else adapterStatus[name] = true;
    }
    return respond(200, {
      ok: true,
      routerName,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      adapters: adapterStatus
    });
  }

  if (req.method === 'POST' && req.url === '/route') {
    if (req.headers['x-clack-token'] !== sharedToken) {
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

for (const [name, adapter] of Object.entries(adapters)) {
  if (adapter.type === 'ws-rpc') getOrCreateAdapterState(name);
}

server.listen(port, '0.0.0.0', () => {
  console.log(`[clack-router] ${routerName} listening on :${port}`);
});
