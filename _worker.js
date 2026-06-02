import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');
    const url = new URL(request.url);
    
    // Deteksi protokol berdasarkan path atau parameter
    const protocol = url.searchParams.get('protocol') || 'trojan';
    
    if (upgradeHeader === 'websocket' || upgradeHeader === 'httpupgrade') {
      // Kirimkan protocol ke handleTunnel
      return handleTunnel(request, ctx, protocol);
    }
    
    return new Response('<html><body><h1>Proxy Tunnel Ready</h1><p>Gunakan parameter ?protocol=trojan atau ?protocol=vless</p></body></html>', {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
    });
  }
};

function handleTunnel(request, ctx, protocol) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  
  server.accept();
  
  const state = {
    tcpSocket: null,
    writer: null,
    connected: false,
    queue: [],
    processing: false,
    protocol: protocol, // Simpan protokol yang digunakan
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
    let address, port, rawDataIndex;
    
    // Pilih parser berdasarkan protokol
    if (state.protocol === 'vless') {
      const result = parseVLESSHeader(buffer);
      address = result.address;
      port = result.port;
      rawDataIndex = result.rawDataIndex;
    } else {
      // Default ke Trojan
      const result = parseTrojanHeader(buffer);
      address = result.address;
      port = result.port;
      rawDataIndex = result.rawDataIndex;
    }
    
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
    const dataToWrite = buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    await state.writer.write(dataToWrite);
  }
}

// PARSER VLESS
function parseVLESSHeader(buffer) {
  if (!(buffer instanceof ArrayBuffer)) {
    buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }
  
  if (buffer.byteLength < 40) throw new Error('Header VLESS terlalu pendek');
  
  const view = new DataView(buffer);
  
  // Validasi protocol version (harus 0)
  const version = view.getUint8(0);
  if (version !== 0) throw new Error('Versi VLESS tidak valid');
  
  // UUID adalah 16 byte (byte 1-16)
  // Byte 17 = command (1=TCP, 2=UDP)
  const command = view.getUint8(17);
  if (command !== 1 && command !== 2) throw new Error('Command tidak valid');
  
  // Port (byte 18-19)
  const port = view.getUint16(18);
  
  // Address type di byte 20
  const addressType = view.getUint8(20);
  
  const { address, nextIndex } = readVLESSAddress(view, buffer, 21, addressType);
  
  // Cari CRLF di akhir header (byte berikutnya bisa jadi 0x0d 0x0a)
  let rawDataIndex = nextIndex;
  if (rawDataIndex + 2 <= buffer.byteLength) {
    if (view.getUint8(rawDataIndex) === 0x0d && view.getUint8(rawDataIndex + 1) === 0x0a) {
      rawDataIndex += 2;
    }
  }
  
  return { address, port, rawDataIndex };
}

function readVLESSAddress(view, buffer, startIndex, addressType) {
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
    for (let i = 0; i < 8; i++) {
      parts.push(view.getUint16(startIndex + i * 2).toString(16));
    }
    return { address: parts.join(':'), nextIndex: startIndex + 16 };
  }
  
  throw new Error('Tipe alamat tidak didukung');
}

// PARSER TROJAN (kode Anda yang sudah ada)
function parseTrojanHeader(buffer) {
  if (!(buffer instanceof ArrayBuffer)) {
    buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }
  
  if (buffer.byteLength < 62) throw new Error('Header Trojan terlalu pendek');
  
  const view = new DataView(buffer);
  
  const cr = view.getUint8(56);
  const lf = view.getUint8(57);
  if (cr !== 0x0d || lf !== 0x0a) {
    throw new Error('Koneksi ditolak: Bukan protokol Trojan valid');
  }
  
  const port = view.getUint16(59);
  const addrTypeIndex = 61;
  const addressType = view.getUint8(addrTypeIndex);
  
  const { address, nextIndex } = readTrojanAddress(view, buffer, addrTypeIndex + 1, addressType);
  
  let rawDataIndex = nextIndex;
  if (rawDataIndex + 2 <= buffer.byteLength) {
    if (view.getUint8(rawDataIndex) === 0x0d && view.getUint8(rawDataIndex + 1) === 0x0a) {
      rawDataIndex += 2;
    }
  }
  
  return { address, port, rawDataIndex };
}

function readTrojanAddress(view, buffer, startIndex, addressType) {
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