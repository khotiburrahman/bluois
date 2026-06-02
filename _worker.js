import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');

    // Hanya menerima koneksi WebSocket atau HTTPUpgrade
    if (upgradeHeader === 'websocket' || upgradeHeader === 'httpupgrade') {
      return handleTunnel(request, ctx);
    }

    return new Response('<html><body><h1>Trojan Tunnel Ready</h1></body></html>', {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
    });
  }
};

function handleTunnel(request, ctx) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);

  server.accept();

  const state = {
    tcpSocket: null,
    writer: null,
    connected: false,
    queue: [],
    processing: false,
  };

  server.addEventListener('message', async (event) => {
    try {
      const buf = event.data instanceof ArrayBuffer
        ? event.data
        : event.data.buffer?.slice(event.data.byteOffset, event.data.byteOffset + event.data.byteLength)
          ?? event.data;

      state.queue.push(buf);
      if (!state.processing) {
        state.processing = true;
        await drainQueue(server, state).catch(() => cleanup(state));
        state.processing = false;
      }
    } catch {
      cleanup(state);
    }
  });

  server.addEventListener('close', () => cleanup(state));
  server.addEventListener('error', () => cleanup(state));

  // Keepalive ping biner setiap 20 detik
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

  ctx.waitUntil(new Promise((resolve) => {
    server.addEventListener('close', () => { clearInterval(timer); resolve(); });
    server.addEventListener('error', () => { clearInterval(timer); resolve(); });
  }));

  // Cloudflare otomatis menyusun HTTP 101 Handshake lewat properti webSocket ini
  return new Response(null, {
    status: 101,
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
    // Memproses header Trojan
    const { address, port, rawDataIndex } = parseTrojanHeader(buffer);

    state.tcpSocket = connect(
      { hostname: address, port: port },
      { allowHalfOpen: false }
    );
    state.writer = state.tcpSocket.writable.getWriter();
    state.connected = true;

    const binaryData = new Uint8Array(buffer);
    if (binaryData.byteLength > rawDataIndex) {
      const payload = binaryData.subarray(rawDataIndex);
      await state.writer.write(payload);
    }

    // Pipe data balik dari Target Server -> Worker -> Client
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
    // Teruskan sisa aliran data biner stream
    const dataToWrite = buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    await state.writer.write(dataToWrite);
  }
}

function cleanup(state) {
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

// ─── PARSER KHUSUS TROJAN PROTOKOL ───────────────────────────────────────────

function parseTrojanHeader(buffer) {
  if (!(buffer instanceof ArrayBuffer)) {
    buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }

  if (buffer.byteLength < 62) throw new Error('Header Trojan terlalu pendek');

  const view = new DataView(buffer);
  
  // Validasi pembatas CRLF (\r\n) setelah 56 byte password hash
  const cr = view.getUint8(56);
  const lf = view.getUint8(57);
  if (cr !== 0x0d || lf !== 0x0a) {
    throw new Error('Koneksi ditolak: Bukan protokol Trojan valid');
  }

  // Byte 58 = command (1=TCP, 3=UDP). Port berada di byte 59-60
  const port = view.getUint16(59);
  const addrTypeIndex = 61;
  const addressType = view.getUint8(addrTypeIndex);
  
  const { address, nextIndex } = readAddress(view, buffer, addrTypeIndex + 1, addressType);
  
  let rawDataIndex = nextIndex;
  // Potong jeda CRLF tambahan milik handshake Trojan sebelum meneruskan payload ke server tujuan
  if (rawDataIndex + 2 <= buffer.byteLength) {
    if (view.getUint8(rawDataIndex) === 0x0d && view.getUint8(rawDataIndex + 1) === 0x0a) {
      rawDataIndex += 2;
    }
  }
  
  return { address, port, rawDataIndex };
}

function readAddress(view, buffer, startIndex, addressType) {
  if (addressType === 1) { // IPv4
    if (buffer.byteLength < startIndex + 4) throw new Error('IPv4 terpotong');
    const address = Array.from(new Uint8Array(buffer, startIndex, 4)).join('.');
    return { address, nextIndex: startIndex + 4 };
  }

  if (addressType === 3) { // Domain Name
    const len = view.getUint8(startIndex);
    if (buffer.byteLength < startIndex + 1 + len) throw new Error('Domain terpotong');
    const address = new TextDecoder().decode(new Uint8Array(buffer, startIndex + 1, len));
    return { address, nextIndex: startIndex + 1 + len };
  }

  if (addressType === 2) { // IPv6
    if (buffer.byteLength < startIndex + 16) throw new Error('IPv6 terpotong');
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(view.getUint16(startIndex + i * 2).toString(16));
    return { address: parts.join(':'), nextIndex: startIndex + 16 };
  }

  throw new Error('Tipe alamat tidak didukung');
}
