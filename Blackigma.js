import { connect } from 'cloudflare:sockets';

// ================= 1. 定义带区域标识的 ProxyIP 池 =================
const backupIPs = [
  { domain: 'ProxyIP.US.CMLiussss.net', regionCode: 'US' },
  { domain: 'ProxyIP.SG.CMLiussss.net', regionCode: 'SG' },
  { domain: 'ProxyIP.JP.CMLiussss.net', regionCode: 'JP' },
  { domain: 'ProxyIP.HK.CMLiussss.net', regionCode: 'HK' },
  { domain: 'ProxyIP.KR.CMLiussss.net', regionCode: 'KR' },
  { domain: 'ProxyIP.DE.CMLiussss.net', regionCode: 'DE' },
  { domain: 'ProxyIP.GB.CMLiussss.net', regionCode: 'GB' }
];

// ================= 2. 地区映射与邻近关系表 =================
const countryToRegion = {
  US: 'US',
  SG: 'SG',
  JP: 'JP',
  HK: 'HK',
  KR: 'KR',
  DE: 'DE',
  GB: 'GB',
  CN: 'HK',
  TW: 'HK',
  AU: 'SG',
  CA: 'US',
  FR: 'DE',
  IT: 'DE',
  ES: 'DE',
  CH: 'DE',
  AT: 'DE',
  BE: 'DE',
  DK: 'DE',
  NO: 'DE',
  IE: 'GB'
};

const nearbyMap = {
  US: ['SG', 'JP', 'HK', 'KR'],
  SG: ['JP', 'HK', 'KR', 'US'],
  JP: ['SG', 'HK', 'KR', 'US'],
  HK: ['SG', 'JP', 'KR', 'US'],
  KR: ['JP', 'HK', 'SG', 'US'],
  DE: ['GB'],
  GB: ['DE']
};

const allRegions = [...new Set(backupIPs.map(function (x) { return x.regionCode; }))];

const ENABLE_LOG = false;
const CONNECT_DATA_TIMEOUT_MS = 1200;
const MAX_PACKET_SIZE = 8 * 1024 * 1024;

const SERVER_PRESETS = [
  { name: '默认入口', host: '__WORKER_DOMAIN__' },
  { name: 'Ubisoft', host: 'store.ubi.com' },
  { name: '乌克兰 MFA', host: 'mfa.gov.ua' },
  { name: 'NexusMods', host: 'staticdelivery.nexusmods.com' },
  { name: '优选入口', host: '优选.cf.090227.xyz' }
];

function log() {
  if (ENABLE_LOG) {
    console.log.apply(console, arguments);
  }
}

// ================= 3. 智能排序函数 =================
function getSmartProxyList(cfCountry) {
  var workerRegion = 'HK';

  if (cfCountry && countryToRegion[cfCountry]) {
    workerRegion = countryToRegion[cfCountry];
  }

  var nearbyRegions = nearbyMap[workerRegion] || [];
  var priorityRegions = [workerRegion]
    .concat(nearbyRegions)
    .concat(
      allRegions.filter(function (r) {
        return r !== workerRegion && nearbyRegions.indexOf(r) === -1;
      })
    );

  var sortedIPs = [];
  for (var i = 0; i < priorityRegions.length; i++) {
    var region = priorityRegions[i];
    var regionIPs = backupIPs.filter(function (ip) {
      return ip.regionCode === region;
    });
    if (regionIPs.length > 0) {
      sortedIPs = sortedIPs.concat(regionIPs);
    }
  }

  return sortedIPs.map(function (ip) {
    return ip.domain;
  });
}

function stringifyUUID(arr) {
  var byteToHex = [];
  for (var i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
  }
  return (
    byteToHex[arr[0]] +
    byteToHex[arr[1]] +
    byteToHex[arr[2]] +
    byteToHex[arr[3]] + '-' +
    byteToHex[arr[4]] +
    byteToHex[arr[5]] + '-' +
    byteToHex[arr[6]] +
    byteToHex[arr[7]] + '-' +
    byteToHex[arr[8]] +
    byteToHex[arr[9]] + '-' +
    byteToHex[arr[10]] +
    byteToHex[arr[11]] +
    byteToHex[arr[12]] +
    byteToHex[arr[13]] +
    byteToHex[arr[14]] +
    byteToHex[arr[15]]
  ).toLowerCase();
}

function isValidUUID(uuid) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

function safeCloseWebSocket(ws) {
  try {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CLOSING)) {
      ws.close();
    }
  } catch (e) {}
}

async function safeCloseSocket(sock) {
  if (!sock) return;
  try {
    await sock.close();
  } catch (e) {}
}

function concatBytes(a, b) {
  var out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function parseVLESSPacket(buffer, expectedUUID) {
  if (!(buffer instanceof ArrayBuffer)) {
    throw new Error('Invalid packet type');
  }

  if (buffer.byteLength < 24) {
    throw new Error('Packet too short');
  }

  if (buffer.byteLength > MAX_PACKET_SIZE) {
    throw new Error('Packet too large');
  }

  var u8 = new Uint8Array(buffer);
  var offset = 0;

  // version
  offset += 1;

  // uuid
  if (offset + 16 > u8.length) {
    throw new Error('Invalid UUID field');
  }
  var uuidBytes = u8.slice(offset, offset + 16);
  offset += 16;

  var clientUUID = stringifyUUID(uuidBytes);
  if (clientUUID !== expectedUUID) {
    throw new Error('UUID mismatch');
  }

  // opt length
  if (offset + 1 > u8.length) {
    throw new Error('Missing opt length');
  }
  var optLength = u8[offset];
  offset += 1;

  if (offset + optLength > u8.length) {
    throw new Error('Invalid opt length');
  }
  offset += optLength;

  // command
  if (offset + 1 > u8.length) {
    throw new Error('Missing command');
  }
  var command = u8[offset];
  offset += 1;

  // only TCP
  if (command !== 0x01) {
    throw new Error('Unsupported command: ' + command);
  }

  // port
  if (offset + 2 > u8.length) {
    throw new Error('Missing port');
  }
  var portRemote = new DataView(buffer, offset, 2).getUint16(0);
  offset += 2;

  // address type
  if (offset + 1 > u8.length) {
    throw new Error('Missing address type');
  }
  var addressType = u8[offset];
  offset += 1;

  var addressRemote = '';

  if (addressType === 1) {
    if (offset + 4 > u8.length) {
      throw new Error('Invalid IPv4 length');
    }
    addressRemote = u8[offset] + '.' + u8[offset + 1] + '.' + u8[offset + 2] + '.' + u8[offset + 3];
    offset += 4;
  } else if (addressType === 2) {
    if (offset + 1 > u8.length) {
      throw new Error('Missing domain length');
    }
    var domainLength = u8[offset];
    offset += 1;

    if (domainLength < 1 || offset + domainLength > u8.length) {
      throw new Error('Invalid domain length');
    }

    addressRemote = new TextDecoder().decode(u8.slice(offset, offset + domainLength));
    offset += domainLength;
  } else if (addressType === 3) {
    if (offset + 16 > u8.length) {
      throw new Error('Invalid IPv6 length');
    }
    var ipv6Bytes = u8.slice(offset, offset + 16);
    var ipv6 = [];
    for (var i = 0; i < 16; i += 2) {
      ipv6.push(((ipv6Bytes[i] << 8) | ipv6Bytes[i + 1]).toString(16));
    }
    addressRemote = ipv6.join(':');
    offset += 16;
  } else {
    throw new Error('Unsupported address type: ' + addressType);
  }

  var rawClientData = buffer.slice(offset);

  return {
    addressRemote: addressRemote,
    portRemote: portRemote,
    rawClientData: rawClientData
  };
}

function wait(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// ================= 4. 配置生成 =================
function buildVlessLink(uuid, serverHost, wsHost) {
  return 'vless://' + uuid + '@' + serverHost + ':443'
    + '?encryption=none'
    + '&security=tls'
    + '&sni=' + encodeURIComponent(wsHost)
    + '&type=ws'
    + '&host=' + encodeURIComponent(wsHost)
    + '&path=%2F'
    + '&fp=chrome'
    + '&ech=cloudflare-ech.com'
    + '#CF-VLESS-Node';
}

function buildYamlConfig(uuid, serverHost, wsHost) {
  return [
    '- name: "CF-Worker-VLESS"',
    '  type: vless',
    '  server: ' + serverHost,
    '  port: 443',
    '  uuid: ' + uuid,
    '  udp: true',
    '  tls: true',
    '  servername: ' + wsHost,
    '  client-fingerprint: chrome',
    '  network: ws',
    '  ech-opts:',
    '    enable: true',
    '    query-server-name: cloudflare-ech.com',
    '  ws-opts:',
    '    path: "/"',
    '    headers:',
    '      Host: ' + wsHost
  ].join('\n');
}

// ================= 5. UI =================
var globalStyles = '\
:root {\
  --primary: #00ff88;\
  --bg: #0f172a;\
  --card: rgba(30, 41, 59, 0.72);\
  --border: rgba(255,255,255,0.1);\
  --muted: #94a3b8;\
}\
* {\
  margin: 0;\
  padding: 0;\
  box-sizing: border-box;\
  font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;\
}\
body {\
  background: var(--bg);\
  color: #fff;\
  display: flex;\
  justify-content: center;\
  align-items: center;\
  min-height: 100vh;\
  overflow: hidden;\
}\
.animated-bg {\
  position: fixed;\
  inset: 0;\
  background: linear-gradient(45deg, #0f172a, #1e1b4b, #064e3b);\
  background-size: 400% 400%;\
  animation: gradientBG 15s ease infinite;\
  z-index: -1;\
}\
@keyframes gradientBG {\
  0% { background-position: 0% 50%; }\
  50% { background-position: 100% 50%; }\
  100% { background-position: 0% 50%; }\
}\
.glass-card {\
  background: var(--card);\
  backdrop-filter: blur(12px);\
  border: 1px solid var(--border);\
  border-radius: 20px;\
  padding: 2.2rem;\
  width: 92%;\
  max-width: 820px;\
  box-shadow: 0 20px 50px rgba(0,0,0,0.45);\
}\
.cursor {\
  color: var(--primary);\
  animation: blink 0.8s infinite;\
}\
@keyframes blink {\
  50% { opacity: 0; }\
}\
h1, h2, h3 {\
  margin-bottom: 12px;\
}\
p {\
  color: var(--muted);\
  line-height: 1.6;\
}\
input, textarea {\
  width: 100%;\
  padding: 12px 14px;\
  margin: 10px 0;\
  background: rgba(0,0,0,0.3);\
  border: 1px solid var(--border);\
  border-radius: 10px;\
  color: var(--primary);\
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;\
  outline: none;\
}\
textarea {\
  resize: vertical;\
  min-height: 240px;\
}\
.server-btn {\
  padding: 7px 13px;\
  background: rgba(255,255,255,0.05);\
  border: 1px solid var(--border);\
  border-radius: 50px;\
  color: #ccc;\
  cursor: pointer;\
  font-size: 0.82rem;\
  transition: 0.25s;\
}\
.server-btn:hover {\
  transform: translateY(-1px);\
  border-color: rgba(255,255,255,0.2);\
}\
.server-btn.active {\
  background: var(--primary);\
  color: #0f172a;\
  border-color: var(--primary);\
  font-weight: 700;\
}\
button.main-btn {\
  width: 100%;\
  padding: 14px;\
  background: var(--primary);\
  color: #0f172a;\
  border: none;\
  border-radius: 10px;\
  font-weight: 800;\
  cursor: pointer;\
  margin-top: 10px;\
}\
button.sub-btn {\
  width: 100%;\
  padding: 14px;\
  background: transparent;\
  color: #999;\
  border: 1px solid #333;\
  border-radius: 10px;\
  font-weight: 700;\
  cursor: pointer;\
  margin-top: 12px;\
}\
.row {\
  display: grid;\
  grid-template-columns: 1fr 1fr;\
  gap: 14px;\
}\
.kv {\
  display: grid;\
  gap: 10px;\
  margin: 18px 0 20px;\
}\
.pill {\
  display: inline-flex;\
  align-items: center;\
  gap: 8px;\
  padding: 7px 12px;\
  border-radius: 999px;\
  background: rgba(255,255,255,0.05);\
  border: 1px solid var(--border);\
  color: #dbeafe;\
  font-size: 0.88rem;\
}\
.dot {\
  width: 8px;\
  height: 8px;\
  border-radius: 999px;\
  background: var(--primary);\
  box-shadow: 0 0 10px var(--primary);\
}\
.tip {\
  font-size: 0.85rem;\
  color: #7dd3fc;\
  margin-top: 6px;\
}\
.notice {\
  margin-top: 12px;\
  font-size: 0.84rem;\
  color: #facc15;\
}\
.copy-row {\
  display: flex;\
  gap: 10px;\
  align-items: center;\
}\
.copy-row input {\
  margin: 10px 0 0;\
}\
.small-btn {\
  margin-top: 10px;\
  padding: 12px 14px;\
  border-radius: 10px;\
  border: 1px solid var(--border);\
  background: rgba(255,255,255,0.04);\
  color: #fff;\
  cursor: pointer;\
  white-space: nowrap;\
}\
@media (max-width: 700px) {\
  .row {\
    grid-template-columns: 1fr;\
  }\
}';

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getHomePage() {
  return '<!DOCTYPE html>\
<html lang="zh-CN">\
<head>\
  <meta charset="UTF-8">\
  <meta name="viewport" content="width=device-width, initial-scale=1.0">\
  <title>Blackigma 登录</title>\
  <style>' + globalStyles + '</style>\
</head>\
<body>\
  <div class="animated-bg"></div>\
  <div class="glass-card" style="max-width:600px; text-align:center">\
    <h1 style="font-size:2rem; margin-bottom:18px">\
      <span id="typewriter"></span><span class="cursor">|</span>\
    </h1>\
    <p style="margin-bottom:18px;">输入 UUID 进入控制台。</p>\
    <input type="password" id="pw" placeholder="输入 UUID" autocomplete="off">\
    <button class="main-btn" id="enterBtn">验证并进入</button>\
    <div class="notice">提示：请输入完整 UUID，例如 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx</div>\
    <script>\
      const txt = ["Here's Blackigma.", "Maybe Eternal?", "Hello World!"];\
      let i = 0, j = 0, cur = "";\
      function type() {\
        if (j < txt[i].length) {\
          cur += txt[i][j++];\
          document.getElementById("typewriter").innerText = cur;\
          setTimeout(type, 100);\
        } else {\
          setTimeout(erase, 1800);\
        }\
      }\
      function erase() {\
        if (j > 0) {\
          cur = txt[i].substring(0, --j);\
          document.getElementById("typewriter").innerText = cur;\
          setTimeout(erase, 45);\
        } else {\
          i = (i + 1) % txt.length;\
          setTimeout(type, 450);\
        }\
      }\
      function go() {\
        const value = document.getElementById("pw").value.trim();\
        const ok = /^[0-9a-fA-F-]{36}$/.test(value);\
        if (!ok) {\
          alert("UUID 格式错误");\
          return;\
        }\
        location.href = "/" + value;\
      }\
      document.getElementById("enterBtn").addEventListener("click", go);\
      document.getElementById("pw").addEventListener("keydown", function (e) {\
        if (e.key === "Enter") go();\
      });\
      type();\
    </script>\
  </div>\
</body>\
</html>';
}

function getDashboard(uuid, domain) {
  var presets = SERVER_PRESETS.map(function (item) {
    return {
      name: item.name,
      host: item.host === '__WORKER_DOMAIN__' ? domain : item.host
    };
  });

  var presetsHtml = presets.map(function (item, index) {
    var active = index === 0 ? ' active' : '';
    return '<button class="server-btn' + active + '" data-h="' + escapeHtml(item.host) + '">' + escapeHtml(item.name) + '</button>';
  }).join('');

  return '<!DOCTYPE html>\
<html lang="zh-CN">\
<head>\
  <meta charset="UTF-8">\
  <meta name="viewport" content="width=device-width, initial-scale=1.0">\
  <title>Blackigma 控制台</title>\
  <style>' + globalStyles + '\
    body {\
      align-items: flex-start;\
      padding: 4vh 0;\
      overflow-y: auto;\
    }\
  </style>\
</head>\
<body>\
  <div class="animated-bg"></div>\
  <div class="glass-card">\
    <h1 style="color:var(--primary); margin-bottom:8px">Blackigma 控制台</h1>\
    <p>切换下方入口地址后，会实时更新 VLESS 链接和 Mihomo 配置。</p>\
    <div class="kv">\
      <div class="row">\
        <div class="pill"><span class="dot"></span>节点状态：正常</div>\
        <div class="pill"><span class="dot"></span>协议：VLESS-WS-TLS</div>\
      </div>\
      <div class="row">\
        <div class="pill">ECH：已启用</div>\
        <div class="pill">UDP：已启用</div>\
      </div>\
    </div>\
    <div style="margin-bottom:20px">\
      <p style="font-size:0.95rem; margin-bottom:10px; color:#e2e8f0">入口地址选择</p>\
      <div style="display:flex; flex-wrap:wrap; gap:8px" id="serverSelector">\
        ' + presetsHtml + '\
      </div>\
      <div class="tip">这里只会修改客户端配置中的 server 字段，不会改变 Worker 后端跳板池。</div>\
    </div>\
    <div>\
      <h3>VLESS 链接</h3>\
      <div class="copy-row">\
        <input type="text" id="v-link" readonly>\
        <button class="small-btn" id="copyLinkBtn">复制链接</button>\
      </div>\
    </div>\
    <div style="margin-top:18px">\
      <h3>Mihomo 配置</h3>\
      <textarea id="c-yaml" readonly></textarea>\
      <button class="small-btn" id="copyYamlBtn" style="width:100%">复制配置</button>\
    </div>\
    <button class="sub-btn" onclick="location.href=\'/\'">退出</button>\
    <script>\
      const uuid = ' + JSON.stringify(uuid) + ';\
      const workerDomain = ' + JSON.stringify(domain) + ';\
      function buildLink(serverHost) {\
        return "vless://" + uuid + "@" + serverHost + ":443"\
          + "?encryption=none"\
          + "&security=tls"\
          + "&sni=" + encodeURIComponent(workerDomain)\
          + "&type=ws"\
          + "&host=" + encodeURIComponent(workerDomain)\
          + "&path=%2F"\
          + "&fp=chrome"\
          + "&ech=cloudflare-ech.com"\
          + "#CF-VLESS-Node";\
      }\
      function buildYaml(serverHost) {\
        return [\
          "- name: \\"CF-Worker-VLESS\\"",\
          "  type: vless",\
          "  server: " + serverHost,\
          "  port: 443",\
          "  uuid: " + uuid,\
          "  udp: true",\
          "  tls: true",\
          "  servername: " + workerDomain,\
          "  client-fingerprint: chrome",\
          "  network: ws",\
          "  ech-opts:",\
          "    enable: true",\
          "    query-server-name: cloudflare-ech.com",\
          "  ws-opts:",\
          "    path: \\"/\\"",\
          "    headers:",\
          "      Host: " + workerDomain\
        ].join("\\n");\
      }\
      function update(serverHost) {\
        document.getElementById("v-link").value = buildLink(serverHost);\
        document.getElementById("c-yaml").value = buildYaml(serverHost);\
      }\
      async function copyText(text) {\
        try {\
          await navigator.clipboard.writeText(text);\
          alert("已复制");\
        } catch (e) {\
          const ta = document.createElement("textarea");\
          ta.value = text;\
          document.body.appendChild(ta);\
          ta.select();\
          document.execCommand("copy");\
          ta.remove();\
          alert("已复制");\
        }\
      }\
      update(workerDomain);\
      document.getElementById("serverSelector").addEventListener("click", function (e) {\
        if (e.target.tagName === "BUTTON") {\
          document.querySelectorAll(".server-btn").forEach(function (btn) {\
            btn.classList.remove("active");\
          });\
          e.target.classList.add("active");\
          update(e.target.dataset.h);\
        }\
      });\
      document.getElementById("copyLinkBtn").addEventListener("click", function () {\
        copyText(document.getElementById("v-link").value);\
      });\
      document.getElementById("copyYamlBtn").addEventListener("click", function () {\
        copyText(document.getElementById("c-yaml").value);\
      });\
    </script>\
  </div>\
</body>\
</html>';
}

export default {
  async fetch(request, env, ctx) {
    try {
      var WORKER_UUID = String(env.UUID || 'd342d11e-d424-4583-b36e-524ab1f0afa4').toLowerCase();

      if (!isValidUUID(WORKER_UUID)) {
        return new Response('Invalid UUID', { status: 500 });
      }

      var url = new URL(request.url);
      var domain = url.hostname;

      // 先处理 WebSocket，避免 "/" 被页面路由截走
      var upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        var webSocketPair = new WebSocketPair();
        var pairValues = Object.values(webSocketPair);
        var client = pairValues[0];
        var server = pairValues[1];
        server.accept();

        var cfCountry = request.cf && request.cf.country ? request.cf.country : '';
        var smartProxyList = getSmartProxyList(cfCountry);

        ctx.waitUntil(handleVLESSSession(server, WORKER_UUID, smartProxyList));

        return new Response(null, {
          status: 101,
          webSocket: client
        });
      }

      if (url.pathname === '/') {
        return new Response(getHomePage(), {
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store'
          }
        });
      }

      if (url.pathname === '/' + WORKER_UUID) {
        return new Response(getDashboard(WORKER_UUID, domain), {
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store'
          }
        });
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      return new Response(String(err), { status: 500 });
    }
  }
};

async function handleVLESSSession(webSocket, expectedUUID, smartProxyList) {
  var activeTcpSocket = null;
  var vlessResponseHeader = new Uint8Array([0, 0]);
  var isFirstPacket = true;
  var closed = false;
  var currentPipeAbort = null;
  var activeConnectionId = 0;

  async function cleanup() {
    if (closed) return;
    closed = true;
    activeConnectionId++;

    if (currentPipeAbort) {
      try {
        currentPipeAbort.abort();
      } catch (e) {}
    }

    await safeCloseSocket(activeTcpSocket);
    activeTcpSocket = null;
    safeCloseWebSocket(webSocket);
  }

  async function connectAndPipe(host, port, rawClientData) {
    var socket = null;
    var firstChunkPromiseResolve = null;
    var firstChunkPromiseDone = false;

    var firstChunkPromise = new Promise(function (resolve) {
      firstChunkPromiseResolve = resolve;
    });

    var abortController = new AbortController();
    currentPipeAbort = abortController;

    var connectionId = ++activeConnectionId;

    try {
      socket = connect({ hostname: host, port: port });
      activeTcpSocket = socket;

      var writer = socket.writable.getWriter();
      try {
        if (rawClientData && rawClientData.byteLength > 0) {
          await writer.write(rawClientData);
        }
      } finally {
        writer.releaseLock();
      }

      socket.readable.pipeTo(
        new WritableStream({
          write: async function (chunk) {
            if (!firstChunkPromiseDone) {
              firstChunkPromiseDone = true;
              if (firstChunkPromiseResolve) {
                firstChunkPromiseResolve(true);
              }
            }

            if (closed) return;
            if (connectionId !== activeConnectionId) return;
            if (activeTcpSocket !== socket) return;
            if (webSocket.readyState !== WebSocket.OPEN) return;

            try {
              if (vlessResponseHeader) {
                var merged = concatBytes(vlessResponseHeader, new Uint8Array(chunk));
                webSocket.send(merged.buffer);
                vlessResponseHeader = null;
              } else {
                webSocket.send(chunk);
              }
            } catch (e) {
              await cleanup();
            }
          },
          close: async function () {
            if (!firstChunkPromiseDone) {
              firstChunkPromiseDone = true;
              if (firstChunkPromiseResolve) {
                firstChunkPromiseResolve(false);
              }
            }
          },
          abort: async function () {
            if (!firstChunkPromiseDone) {
              firstChunkPromiseDone = true;
              if (firstChunkPromiseResolve) {
                firstChunkPromiseResolve(false);
              }
            }
          }
        }),
        { signal: abortController.signal }
      ).catch(function () {});

      var result = await Promise.race([
        firstChunkPromise,
        wait(CONNECT_DATA_TIMEOUT_MS).then(function () { return false; })
      ]);

      if (!result) {
        if (connectionId === activeConnectionId) {
          activeConnectionId++;
        }

        try {
          abortController.abort();
        } catch (e) {}

        await safeCloseSocket(socket);
        if (activeTcpSocket === socket) {
          activeTcpSocket = null;
        }
        return false;
      }

      return true;
    } catch (e) {
      if (!firstChunkPromiseDone) {
        firstChunkPromiseDone = true;
        if (firstChunkPromiseResolve) {
          firstChunkPromiseResolve(false);
        }
      }

      if (connectionId === activeConnectionId) {
        activeConnectionId++;
      }

      try {
        abortController.abort();
      } catch (e2) {}

      await safeCloseSocket(socket);
      if (activeTcpSocket === socket) {
        activeTcpSocket = null;
      }
      return false;
    }
  }

  webSocket.addEventListener('message', async function (event) {
    if (closed) return;

    try {
      var vlessBuffer;

      if (event.data instanceof ArrayBuffer) {
        vlessBuffer = event.data;
      } else if (typeof Blob !== 'undefined' && event.data instanceof Blob) {
        vlessBuffer = await event.data.arrayBuffer();
      } else {
        throw new Error('Unsupported message type');
      }

      if (isFirstPacket) {
        isFirstPacket = false;

        var parsed = parseVLESSPacket(vlessBuffer, expectedUUID);
        var addressRemote = parsed.addressRemote;
        var portRemote = parsed.portRemote;
        var rawClientData = parsed.rawClientData;

        log('[状态] 1. 尝试直连: ' + addressRemote + ':' + portRemote);
        var connectionSuccess = await connectAndPipe(addressRemote, portRemote, rawClientData);

        if (!connectionSuccess) {
          log('[拦截] 直连失败，启动智能跳板列表');

          for (var i = 0; i < smartProxyList.length; i++) {
            var fallbackHost = smartProxyList[i];
            log('[状态] 2. 尝试备用跳板: ' + fallbackHost + ':' + portRemote);
            connectionSuccess = await connectAndPipe(fallbackHost, portRemote, rawClientData);

            if (connectionSuccess) {
              log('[成功] 已连接至跳板: ' + fallbackHost + ':' + portRemote);
              break;
            } else {
              log('[跳板异常] ' + fallbackHost + ':' + portRemote + ' 失败，尝试下一个');
            }
          }

          if (!connectionSuccess) {
            log('[彻底失败] 直连和所有备用跳板均失败');
            await cleanup();
          }
        }

        return;
      }

      if (!activeTcpSocket) {
        await cleanup();
        return;
      }

      var writer = activeTcpSocket.writable.getWriter();
      try {
        await writer.write(vlessBuffer);
      } finally {
        writer.releaseLock();
      }
    } catch (err) {
      log('message error:', err);
      await cleanup();
    }
  });

  webSocket.addEventListener('close', function () {
    cleanup();
  });

  webSocket.addEventListener('error', function () {
    cleanup();
  });
}
