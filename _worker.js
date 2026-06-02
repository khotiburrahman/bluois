import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');

    if (upgradeHeader === 'websocket') {
      return handleTunnel(request, ctx);
    }

    return new Response('<html><body><h1>Service Ready</h1></body></html>', {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
    });
  },

  // Handler untuk Hibernatable WebSocket (wajib untuk tunnel jangka panjang)
  async webSocketMessage(ws, message) {
    await ws.env_handleMessage(message);
  },

  async webSocketClose(ws, code, reason) {
    ws.env_cleanup?.();
  },

  async webSocketError(ws, error) {
    ws.env_cleanup?.();
  }
};

function handleTunnel(request, ctx) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);

  // Gunakan acceptWebSocket (Hibernatable API) bukan server.accept()
  // Ini yang menjaga koneksi tetap hidup melewati batas CPU time normal
  const state = {
    tcpSocket: null,
    writer: null,
    connected: false,
    queue: [],
    processing: false,
  };

  // Simpan state di properti WebSocket itu sendiri
  server._state = state;

  server.accept();

  // Attach handler langsung ke objek
  server.addEventListener('message', async (event) => {
    const buf = event.data instanceof ArrayBuffer
      ? event.data
      : event.data.buffer?.slice(event.data.byteOffset, event.data.byteOffset + event.data.byteLength)
        ?? event.data;

    state.queue.push(buf);
    if (!state.processing) {
      state.processing = true;
      await drainQueue(server, state).catch(() => cleanup(server, state));
      state.processing = false;
    }
  });

  server.addEventListener('close', () => cleanup(server, state));
  server.addEventListener('error', () => cleanup(server, state));

  // Keepalive: kirim ping setiap 20 detik
  const timer = setInterval(() => {
    try {
      if (server.readyState === 1) {
        server.send(new Uint8Array(0));
      } else {
        clearInterval(timer);
      }
    } catch {
      clearInterval(timer);
    }
  }, 20000);

  // waitUntil dengan Promise yang tidak resolve sampai WS tutup
  ctx.waitUntil(new Promise((resolve) => {
    server.addEventListener('close', resolve);
    server.addEventListener('error', resolve);
  }));

  return new Response(null, {
    status: 101,
    statusText: 'Switching Protocols',
    webSocket: client,
  });
}

async function drainQueue(server, state) {
  while (state.queue.length > 0) {
    const buffer = state.queue.shift();
    await processMessage(server, state, buffer);
  }
}

async function processMessage(server, state, buffer) {
  if (!state.connected) {
    const { address, port, rawDataIndex } = parseFastHeader(buffer);

    state.tcpSocket = connect(
      { hostname: address, port: port },
      { allowHalfOpen: false }
    );
    state.writer = state.tcpSocket.writable.getWriter();
    state.connected = true;

    if (buffer.byteLength > rawDataIndex) {
      await state.writer.write(new Uint8Array(buffer, rawDataIndex));
    }

    // Pipe VPS → Client
    state.tcpSocket.readable
      .pipeTo(new WritableStream({
        write(chunk) {
          if (server.readyState === 1) {
            server.send(chunk);
          } else {
            throw new Error('ws closed');
          }
        },
        close() { safeClose(server); },
        abort() { safeClose(server); },
      }))
      .catch(() => safeClose(server));

  } else {
    await state.writer.write(
      buffer instanceof ArrayBuffer
        ? new Uint8Array(buffer)
        : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength)
    );
  }
}

function cleanup(server, state) {
  safeClose(server);
  try { state.writer?.releaseLock(); } catch {}
  try { state.tcpSocket?.close(); } catch {}
  state.writer = null;
  state.tcpSocket = null;
  state.connected = false;
}

function safeClose(ws) {
  try {
    if (ws.readyState < 2) ws.close(1000, 'done');
  } catch {}
}

// ─── PARSER HEADER ────────────────────────────────────────────────────────────

function parseFastHeader(buffer) {
  if (!(buffer instanceof ArrayBuffer)) {
    buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }

  if (buffer.byteLength < 20) throw new Error('Header terlalu pendek');

  const view = new DataView(buffer);
  const firstByte = view.getUint8(0);

  // VLESS: byte[0] = 0 (version)
  if (firstByte === 0) {
    const addonsLen = view.getUint8(17);
    const portIndex = 18 + addonsLen + 1; // skip addons + cmd
    const port = view.getUint16(portIndex);
    const addrTypeIndex = portIndex + 2;
    const addressType = view.getUint8(addrTypeIndex);
    const { address, nextIndex } = readAddress(view, buffer, addrTypeIndex + 1, addressType);
    return { address, port, rawDataIndex: nextIndex };
  }

  // Trojan: 56 byte hash + \r\n + cmd(1) + port(2) + atype(1)
  if (buffer.byteLength >= 62) {
    const cr = view.getUint8(56);
    const lf = view.getUint8(57);
    if (cr === 0x0d && lf === 0x0a) {
      const port = view.getUint16(59); // skip cmd(58) → port(59)
      const addrTypeIndex = 61;
      const addressType = view.getUint8(addrTypeIndex);
      const { address, nextIndex } = readAddress(view, buffer, addrTypeIndex + 1, addressType);
      return { address, port, rawDataIndex: nextIndex };
    }
  }

  throw new Error('Format header tidak dikenali (bukan VLESS atau Trojan)');
}

function readAddress(view, buffer, startIndex, addressType) {
  if (addressType === 1) {
    // IPv4
    if (buffer.byteLength < startIndex + 4) throw new Error('IPv4 truncated');
    const address = Array.from(new Uint8Array(buffer, startIndex, 4)).join('.');
    return { address, nextIndex: startIndex + 4 };
  }

  if (addressType === 3) {
    // Domain
    const len = view.getUint8(startIndex);
    if (buffer.byteLength < startIndex + 1 + len) throw new Error('Domain truncated');
    const address = new TextDecoder().decode(new Uint8Array(buffer, startIndex + 1, len));
    return { address, nextIndex: startIndex + 1 + len };
  }

  if (addressType === 2) {
    // IPv6
    if (buffer.byteLength < startIndex + 16) throw new Error('IPv6 truncated');
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(view.getUint16(startIndex + i * 2).toString(16));
    return { address: parts.join(':'), nextIndex: startIndex + 16 };
  }

  throw new Error(`Tipe address tidak dikenal: ${addressType}`);
}