/**
 * ==============================================================================
 * Project: Blackigma Edge 10.3 (Production-Grade Final Stable)
 * Type: Stateless Zero-Lock-Async-Verified Dynamic-Cache Serverless VLESS Edge Router
 * ==============================================================================
 */

import { connect } from 'cloudflare:sockets';

const CONFIG = {
  DEFAULT_UUID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',

  PROXY_POOL: [
    { domain: 'ProxyIP.SG.CMLiussss.net', port: 443, region: 'SG' },
    { domain: 'ProxyIP.JP.CMLiussss.net', port: 443, region: 'JP' },
    { domain: 'ProxyIP.HK.CMLiussss.net', port: 443, region: 'HK' },
    { domain: 'ProxyIP.US.CMLiussss.net', port: 443, region: 'US' },
  ],

  SUPPORTED_TLS_PORTS: new Set([443, 8443, 2053, 2083, 2087, 2096]),

  // 超时与错峰预算
  CONNECT_TIMEOUT_MS: 1500,
  DIRECT_PROXY_DELAY_MS: 150,         // 3路阶梯错峰 (0ms -> 150ms -> 300ms)

  // 内存 / 背压 / 限制
  MAX_PENDING_BYTES: 1024 * 1024,     // 1MB 传输背压
  MAX_PREQUEUE_BYTES: 512 * 1024,     // 握手预排队上限 512KB
  MAX_MESSAGE_BYTES: 1024 * 1024,     // 1MB
  MAX_HEADER_BYTES: 8 * 1024,         // 8KB 防 Slowloris
  MAX_CONNECTIONS: 25,                // 【10.3 优化】：微调至 25 甜点区，平衡多设备并发与内存

  // Idle 闲置释放
  MOBILE_IDLE_TIMEOUT_MS: 300000,     // 300秒
  DESKTOP_IDLE_TIMEOUT_MS: 600000,    // 600秒

  MAX_CACHE_ENTRIES: 64,
  WS_PATH: '/',
};

// Colo 静态区域优先级映射
const COLO_PRIORS = {
  HKG: ['HK', 'JP', 'SG', 'US'],
  SIN: ['SG', 'HK', 'JP', 'US'],
  NRT: ['JP', 'HK', 'SG', 'US'],
  KIX: ['JP', 'HK', 'SG', 'US'],
  TPE: ['HK', 'JP', 'SG', 'US'],
  SJC: ['US', 'JP', 'HK', 'SG'],
  LAX: ['US', 'JP', 'HK', 'SG'],
  LHR: ['US', 'SG', 'HK', 'JP'],
  FRA: ['US', 'SG', 'HK', 'JP'],
};

// 全局状态与内存防爆保护
let ACTIVE_CONNECTIONS = 0;
const PROXY_FAIL_MEMORY = new Map();     // 失败冷却映射 { [domain]: cooldownUntil }
const PROXY_LATENCY_CACHE = new Map();   // 动态延迟感知 { [domain]: { rtt, expires } }

// 经典 LRU Map
class BoundedLruMap extends Map {
  constructor(maxSize) {
    super();
    this.maxSize = maxSize;
  }
  set(key, value) {
    if (this.has(key)) {
      this.delete(key);
    } else if (this.size >= this.maxSize) {
      const oldestKey = this.keys().next().value;
      this.delete(oldestKey);
    }
    return super.set(key, value);
  }
  get(key) {
    if (!this.has(key)) return undefined;
    const value = super.get(key);
    this.delete(key);
    super.set(key, value);
    return value;
  }
}

const TARGET_ROUTE_CACHE = new BoundedLruMap(CONFIG.MAX_CACHE_ENTRIES);
const TD = new TextDecoder();

// ==============================================================================
// [工具函数]
// ==============================================================================

function parseUuidToBytes(uuidStr) {
  const clean = String(uuidStr).replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(clean)) throw new Error('Invalid UUID');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function normalizeUuidString(uuid) {
  const clean = String(uuid || '').replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(clean)) return null;
  return [clean.slice(0, 8), clean.slice(8, 12), clean.slice(12, 16), clean.slice(16, 20), clean.slice(20, 32)].join('-');
}

let CACHED_UUID_BYTES = null;
let LAST_RAW_UUID = null;

function getUuidBytes(env) {
  const raw = String(env?.UUID || CONFIG.DEFAULT_UUID);
  if (raw === LAST_RAW_UUID && CACHED_UUID_BYTES) return CACHED_UUID_BYTES;
  LAST_RAW_UUID = raw;
  CACHED_UUID_BYTES = parseUuidToBytes(raw);
  return CACHED_UUID_BYTES;
}

function getConfiguredUuid(env) {
  return normalizeUuidString(env?.UUID || CONFIG.DEFAULT_UUID);
}

function detectClientEnvironment(request) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const isMobile = /mobile|android|iphone|ipad|phone|clash|sing-box|surge|loon/i.test(ua);
  return {
    isMobile,
    idleTimeoutMs: isMobile ? CONFIG.MOBILE_IDLE_TIMEOUT_MS : CONFIG.DESKTOP_IDLE_TIMEOUT_MS,
  };
}

// ==============================================================================
// [Zero-Lock Asynchronous Probe & 3路错峰竞速]
// ==============================================================================

async function launchProbe(host, port, payload, routeType, abortSignal) {
  const start = Date.now();
  let socket = null;
  let writer = null;
  let handedOff = false;
  let connectTimerId = null;

  const forceCleanup = async () => {
    if (handedOff) return;
    try { socket?.close(); } catch (_) {}
    try { await writer?.abort(); } catch (_) {}
  };

  const abortHandler = () => {
    if (connectTimerId !== null) {
      clearTimeout(connectTimerId);
      connectTimerId = null;
    }
    void forceCleanup();
  };

  abortSignal.addEventListener('abort', abortHandler, { once: true });

  try {
    socket = connect({ hostname: host, port: Number(port) });
    
    const connectTimer = new Promise((_, reject) => {
      connectTimerId = setTimeout(() => {
        reject(new Error('Connect timeout'));
      }, CONFIG.CONNECT_TIMEOUT_MS);
    });

    try {
      await Promise.race([socket.opened, connectTimer]);
    } finally {
      if (connectTimerId !== null) {
        clearTimeout(connectTimerId);
        connectTimerId = null;
      }
    }

    if (abortSignal.aborted) throw new Error('Abort');

    writer = socket.writable.getWriter();
    await writer.write(payload);
    writer.releaseLock();
    writer = null;

    const rtt = Date.now() - start;

    // 【10.3 核心修复】：彻底抛弃后台 reader.read() 导致的流锁定冲突，改用 socket.closed 零冲突监听
    if (routeType === 'PROXY') {
      socket.closed.catch(() => {
        if (PROXY_FAIL_MEMORY.size > 32) PROXY_FAIL_MEMORY.clear();
        PROXY_FAIL_MEMORY.set(host, Date.now() + 60000);
      });
    }

    handedOff = true;
    if (abortHandler) {
      abortSignal.removeEventListener('abort', abortHandler);
    }

    return {
      socket,
      reader: socket.readable.getReader(),
      firstChunk: null,
      routeType,
      host,
      port,
      rtt,
    };
  } catch (err) {
    if (connectTimerId !== null) clearTimeout(connectTimerId);
    if (abortHandler) abortSignal.removeEventListener('abort', abortHandler);
    await forceCleanup();
    throw err;
  }
}

async function selectEgressRoute(targetHost, targetPort, initialPayload, request) {
  const colo = request.cf?.colo || 'UNKNOWN';
  const targetCacheKey = `${colo}:${targetHost}:${targetPort}`;
  const now = Date.now();

  const isIpTarget = /^(\d{1,3}\.){3}\d{1,3}$/.test(targetHost) || targetHost.includes(':');
  const isTlsEligible = CONFIG.SUPPORTED_TLS_PORTS.has(targetPort) && !isIpTarget;

  // 1. 命中区域缓存 (Fast Path)
  const cached = TARGET_ROUTE_CACHE.get(targetCacheKey);
  if (cached && now < cached.expiresAt) {
    try {
      const socket = connect({ hostname: cached.host, port: Number(cached.port) });
      await socket.opened;
      const writer = socket.writable.getWriter();
      await writer.write(initialPayload);
      writer.releaseLock();
      return {
        socket,
        reader: socket.readable.getReader(),
        firstChunk: null,
        routeType: cached.routeType,
        host: cached.host,
        port: cached.port,
        rtt: cached.rtt,
      };
    } catch (_) {
      TARGET_ROUTE_CACHE.delete(targetCacheKey);
    }
  }

  // 2. 结合静态区域优先级与带 TTL 的动态 RTT 评分排序 Proxy
  const preferredRegions = COLO_PRIORS[colo] || ['SG', 'JP', 'HK', 'US'];
  const sortedProxies = [...CONFIG.PROXY_POOL].sort((a, b) => {
    const entryA = PROXY_LATENCY_CACHE.get(a.domain);
    const entryB = PROXY_LATENCY_CACHE.get(b.domain);
    const latA = (entryA && entryA.expires > now) ? entryA.rtt : 250;
    const latB = (entryB && entryB.expires > now) ? entryB.rtt : 250;

    const idxA = preferredRegions.indexOf(a.region);
    const idxB = preferredRegions.indexOf(b.region);
    const scoreA = (idxA === -1 ? 99 : idxA) * 40 + latA;
    const scoreB = (idxB === -1 ? 99 : idxB) * 40 + latB;
    return scoreA - scoreB;
  });

  const activeProxies = sortedProxies.filter(p => now >= (PROXY_FAIL_MEMORY.get(p.domain) || 0));

  const abortController = new AbortController();
  const racePool = [];

  // 【路 1】：Direct 直连（立即触发）
  racePool.push(launchProbe(targetHost, targetPort, initialPayload, 'DIRECT', abortController.signal));

  // 【路 2】：区域最优 Proxy 1（错峰 150ms）
  if (isTlsEligible && activeProxies.length > 0) {
    const p1 = activeProxies[0];
    racePool.push((async () => {
      await new Promise(r => setTimeout(r, CONFIG.DIRECT_PROXY_DELAY_MS));
      if (abortController.signal.aborted) throw new Error('Aborted');
      try {
        return await launchProbe(p1.domain, p1.port, initialPayload, 'PROXY', abortController.signal);
      } catch (err) {
        if (PROXY_FAIL_MEMORY.size > 32) PROXY_FAIL_MEMORY.clear();
        PROXY_FAIL_MEMORY.set(p1.domain, Date.now() + 60000);
        throw err;
      }
    })());
  }

  // 【路 3】：区域次优 Proxy 2（错峰 300ms）
  if (isTlsEligible && activeProxies.length > 1) {
    const p2 = activeProxies[1];
    racePool.push((async () => {
      await new Promise(r => setTimeout(r, CONFIG.DIRECT_PROXY_DELAY_MS * 2));
      if (abortController.signal.aborted) throw new Error('Aborted');
      try {
        return await launchProbe(p2.domain, p2.port, initialPayload, 'PROXY', abortController.signal);
      } catch (err) {
        if (PROXY_FAIL_MEMORY.size > 32) PROXY_FAIL_MEMORY.clear();
        PROXY_FAIL_MEMORY.set(p2.domain, Date.now() + 60000);
        throw err;
      }
    })());
  }

  try {
    const winner = await Promise.any(racePool);
    abortController.abort();

    // 更新带 TTL (5分钟) 的动态延迟缓存
    if (winner.routeType === 'PROXY') {
      const prevEntry = PROXY_LATENCY_CACHE.get(winner.host);
      const smoothRtt = prevEntry && prevEntry.expires > now ? Math.round(prevEntry.rtt * 0.7 + winner.rtt * 0.3) : winner.rtt;
      PROXY_LATENCY_CACHE.set(winner.host, { rtt: smoothRtt, expires: now + 300000 });
    }

    // 【10.3 优化】：分级异步缓存 TTL（Direct 120s 适应 Anycast 变化，Proxy 60s 抗抖动）
    const ttl = winner.routeType === 'DIRECT' ? 120000 : 60000;
    TARGET_ROUTE_CACHE.set(targetCacheKey, {
      routeType: winner.routeType,
      host: winner.host,
      port: winner.port,
      rtt: winner.rtt,
      expiresAt: now + ttl,
    });

    return winner;
  } catch (err) {
    abortController.abort();
    throw new Error('All egress paths exhausted');
  }
}

// ==============================================================================
// [流式传输与背压管理]
// ==============================================================================

function createLiteStreamPump(winner, clientWs, vlessResponseHeader, idleTimeoutMs, releaseConnFn) {
  const { socket, reader, firstChunk } = winner;
  let writer = null;
  let isTornDown = false;
  let idleTimer = null;
  const writeQueue = [];
  let pendingBytes = 0;
  let isPumping = false;

  const resetIdle = () => {
    if (isTornDown) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => teardown(), idleTimeoutMs);
  };

  const teardown = async () => {
    if (isTornDown) return;
    isTornDown = true;
    if (idleTimer) clearTimeout(idleTimer);

    try { socket?.close(); } catch (_) {}
    try { await writer?.abort(); } catch (_) {}
    try { await reader?.cancel(); } catch (_) {}
    try {
      if (clientWs.readyState === WebSocket.OPEN) clientWs.close(1000);
    } catch (_) {}
    
    releaseConnFn();
  };

  const processQueue = async () => {
    if (isPumping || isTornDown) return;
    isPumping = true;
    try {
      while (writeQueue.length > 0 && !isTornDown) {
        const chunk = writeQueue.shift();
        await writer.write(chunk);
        pendingBytes -= chunk.byteLength;
        resetIdle();
      }
    } catch (_) {
      void teardown();
    } finally {
      isPumping = false;
      if (writeQueue.length > 0 && !isTornDown) void processQueue();
    }
  };

  const enqueue = async (data) => {
    resetIdle();
    if (isTornDown) return;
    const buffer = data instanceof ArrayBuffer ? data : (data.buffer ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) : await data.arrayBuffer());
    
    if (buffer.byteLength > CONFIG.MAX_MESSAGE_BYTES || pendingBytes + buffer.byteLength > CONFIG.MAX_PENDING_BYTES) {
      void teardown();
      return;
    }

    pendingBytes += buffer.byteLength;
    writeQueue.push(buffer);
    void processQueue();
  };

  try {
    if (firstChunk && firstChunk.byteLength > 0) {
      const resBuf = new Uint8Array(vlessResponseHeader.length + firstChunk.length);
      resBuf.set(vlessResponseHeader, 0);
      resBuf.set(firstChunk, vlessResponseHeader.length);
      clientWs.send(resBuf);
    } else {
      clientWs.send(vlessResponseHeader);
    }
    writer = socket.writable.getWriter();
  } catch (_) {
    void teardown();
    return { enqueue, teardown };
  }

  void (async () => {
    try {
      resetIdle();
      while (!isTornDown) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength > 0) {
          if (clientWs.readyState !== WebSocket.OPEN) break;
          resetIdle();
          clientWs.send(value);
        }
      }
    } catch (_) {}
    void teardown();
  })();

  clientWs.addEventListener('close', () => void teardown());
  clientWs.addEventListener('error', () => void teardown());

  return { enqueue, teardown };
}

// ==============================================================================
// [VLESS 解析与 IPv6 格式化]
// ==============================================================================

function formatIpv6(view, offset) {
  const words = [];
  for (let i = 0; i < 8; i++) {
    words.push(view.getUint16(offset + i * 2));
  }
  let s = words.map(w => w.toString(16)).join(':');
  s = s.replace(/(^|:)0(:0)+(:|$)/, '::');
  return s;
}

function tryParseVlessHeader(buffer, expectedUuidBytes) {
  if (buffer.byteLength < 24) return null;
  const view = new DataView(buffer);

  if (view.getUint8(0) !== 0x00) throw new Error('Invalid version');
  const uuidView = new Uint8Array(buffer, 1, 16);
  for (let i = 0; i < 16; i++) {
    if (uuidView[i] !== expectedUuidBytes[i]) throw new Error('Invalid UUID');
  }

  const optLen = view.getUint8(17);
  let offset = 18 + optLen;
  if (buffer.byteLength < offset + 1) return null;

  if (view.getUint8(offset) !== 0x01) throw new Error('Only TCP supported');
  offset += 1;

  if (buffer.byteLength < offset + 2) return null;
  const port = view.getUint16(offset);
  offset += 2;

  if (buffer.byteLength < offset + 1) return null;
  const atyp = view.getUint8(offset);
  offset += 1;

  let targetHost = '';
  if (atyp === 1) {
    if (buffer.byteLength < offset + 4) return null;
    targetHost = [view.getUint8(offset), view.getUint8(offset+1), view.getUint8(offset+2), view.getUint8(offset+3)].join('.');
    offset += 4;
  } else if (atyp === 2) {
    if (buffer.byteLength < offset + 1) return null;
    const len = view.getUint8(offset);
    offset += 1;
    if (buffer.byteLength < offset + len) return null;
    targetHost = TD.decode(buffer.slice(offset, offset + len));
    offset += len;
  } else if (atyp === 3) {
    if (buffer.byteLength < offset + 16) return null;
    targetHost = formatIpv6(view, offset);
    offset += 16;
  } else {
    throw new Error('Unknown atyp');
  }

  return {
    port,
    targetHost,
    payload: buffer.slice(offset),
    vlessResponseHeader: new Uint8Array([0x00, 0x00]),
  };
}

// ==============================================================================
// [配置页生成]
// ==============================================================================

function buildClashYaml(uuid, host) {
  return `
- name: Blackigma-${host}
  type: vless
  server: ${host}
  port: 443
  uuid: ${uuid}
  network: ws
  tls: true
  udp: false
  servername: ${host}
  ws-opts:
    path: /
    headers:
      Host: ${host}
`.trim();
}

function buildSingboxJson(uuid, host) {
  return JSON.stringify({
    type: "vless",
    tag: "Blackigma",
    server: host,
    server_port: 443,
    uuid: uuid,
    tls: { enabled: true, server_name: host },
    transport: { type: "ws", path: "/", headers: { Host: host } }
  }, null, 2);
}

function buildConfigPage(uuid, host) {
  const vlessUri = `vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2F#Blackigma`;
  const clashYaml = buildClashYaml(uuid, host);
  const singbox = buildSingboxJson(uuid, host);

  return `<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width">
<title>Blackigma Edge</title><style>
body{background:#0b0f14;color:#ddd;font-family:sans-serif;padding:20px;max-width:800px;margin:auto;}
textarea{width:100%;height:130px;background:#020617;color:#93c5fd;border:1px solid #334155;border-radius:6px;padding:8px;font-family:monospace;font-size:12px;}
h3{margin-top:18px;font-size:14px;color:#94a3b8;}
</style></head><body>
<h2>Blackigma Edge Personal 10.3</h2>
<h3>VLESS URI</h3><textarea readonly>${vlessUri}</textarea>
<h3>Clash Meta YAML</h3><textarea readonly>${clashYaml}</textarea>
<h3>Sing-box JSON</h3><textarea readonly>${singbox}</textarea>
</body></html>`;
}

// ==============================================================================
// [主入口]
// ==============================================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();

    if (upgrade !== 'websocket') {
      let uuid;
      try { uuid = getConfiguredUuid(env) || CONFIG.DEFAULT_UUID; } catch (_) { uuid = CONFIG.DEFAULT_UUID; }

      const reqPath = url.pathname.toLowerCase().replace(/\/+$/, '');
      const targetPath = `/${uuid}`.toLowerCase();
      const targetPathNoDash = `/${uuid.replace(/-/g, '')}`.toLowerCase();

      // 仅当路径严格匹配实际 UUID（带横杠或不带横杠）时展示面板，其余路径一律返回 OK
      if (reqPath === targetPath || reqPath === targetPathNoDash) {
        return new Response(buildConfigPage(uuid, url.host), {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      return new Response('OK', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      });
    }

    if (ACTIVE_CONNECTIONS >= CONFIG.MAX_CONNECTIONS) {
      return new Response('Too many connections', { status: 429 });
    }

    ACTIVE_CONNECTIONS++;
    let released = false;
    const releaseConnection = () => {
      if (!released) {
        released = true;
        ACTIVE_CONNECTIONS = Math.max(0, ACTIVE_CONNECTIONS - 1);
      }
    };

    let uuidBytes;
    try {
      uuidBytes = getUuidBytes(env);
    } catch (_) {
      releaseConnection();
      return new Response('Invalid UUID', { status: 500 });
    }

    const clientEnv = detectClientEnvironment(request);
    const { 0: clientWs, 1: serverWs } = new WebSocketPair();
    serverWs.binaryType = 'arraybuffer';
    serverWs.accept();

    let accumulated = new Uint8Array(0);
    let streamPump = null;
    let streamReady = false;
    let handshakeDone = false;
    const preQueue = [];
    let preQueueBytes = 0;

    serverWs.addEventListener('message', async (event) => {
      if (streamReady && streamPump) {
        void streamPump.enqueue(event.data);
        return;
      }
      if (handshakeDone) {
        const chunkBuf = event.data instanceof ArrayBuffer ? event.data : await event.data.arrayBuffer();
        if (preQueueBytes + chunkBuf.byteLength > CONFIG.MAX_PREQUEUE_BYTES) {
          try { serverWs.close(1009, 'Pre-queue buffer overflow'); } catch (_) {}
          releaseConnection();
          return;
        }
        preQueueBytes += chunkBuf.byteLength;
        preQueue.push(chunkBuf);
        return;
      }

      try {
        const chunk = event.data instanceof ArrayBuffer ? event.data : await event.data.arrayBuffer();
        if (accumulated.byteLength + chunk.byteLength > CONFIG.MAX_HEADER_BYTES) {
          serverWs.close(1009, 'Header overflow');
          releaseConnection();
          return;
        }
        const next = new Uint8Array(accumulated.byteLength + chunk.byteLength);
        next.set(accumulated, 0);
        next.set(new Uint8Array(chunk), accumulated.byteLength);
        accumulated = next;

        const parsed = tryParseVlessHeader(accumulated.buffer, uuidBytes);
        if (!parsed) return;

        handshakeDone = true;
        accumulated = null;

        const winner = await selectEgressRoute(parsed.targetHost, parsed.port, parsed.payload, request);
        streamPump = createLiteStreamPump(winner, serverWs, parsed.vlessResponseHeader, clientEnv.idleTimeoutMs, releaseConnection);

        while (preQueue.length > 0) {
          await streamPump.enqueue(preQueue.shift());
        }
        streamReady = true;
      } catch (err) {
        try { serverWs.close(1011, 'Handshake error'); } catch (_) {}
        releaseConnection();
      }
    });

    serverWs.addEventListener('error', () => releaseConnection());
    serverWs.addEventListener('close', () => releaseConnection());

    return new Response(null, { status: 101, webSocket: clientWs });
  },
};
