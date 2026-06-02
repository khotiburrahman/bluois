import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');
    const url = new URL(request.url);
    
    // Pisahkan endpoint berdasarkan path
    if (upgradeHeader === 'websocket' || upgradeHeader === 'httpupgrade') {
      if (url.pathname === '/vless') {
        return handleVLESS(request, ctx);
      } else if (url.pathname === '/trojan') {
        return handleTrojan(request, ctx);
      }
      // Default ke trojan jika tidak ada path yang cocok
      return handleTrojan(request, ctx);
    }
    
    // Halaman info
    return new Response(`<html>
<body>
<h1>Proxy Tunnel Ready</h1>
<p>Gunakan endpoint:</p>
<ul>
<li>VLESS: wss://${url.hostname}/vless</li>
<li>Trojan: wss://${url.hostname}/trojan</li>
</ul>
</body>
</html>`, {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
    });
  }
};

// ==================== HANDLER VLESS ====================
function handleVLESS(request, ctx) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  
  // KRUSIAL: Set binaryType dan allowHalfOpen
  server.binaryType = "arraybuffer";
  server.accept({ allowHalfOpen: true });
  
  const state = {
    tcpSocket: null,
    writer: null,
    connected: false,
    queue: [],
    processing: false,
  };
  
  server.addEventListener('message', async (event) => {
    try {
      let buf = event.data;
      if (buf instanceof Blob) {
        buf = await buf.arrayBuffer();
      } else if (!(buf instanceof ArrayBuffer)) {
        buf = buf.buffer?.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) ?? buf;
      }
      
      state.queue.push(buf);
      if (!state.processing) {
        state.processing = true;
        await drainQueueVLESS(server, state).catch(() => cleanup(state));
        state.processing = false;
      }
    } catch (err) {
      console.error('Message error:', err);
      cleanup(state);
    }
  });
  
  server.addEventListener('close', () => {
    clearKeepAlive(state);
    cleanup(state);
  });
  
  server.addEventListener('error', () => {
    clearKeepAlive(state);
    cleanup(state);
  });
  
  // Keep-alive: 30 detik (lebih aman untuk VLESS)
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
  }, 30000);
  
  state.keepAliveTimer = timer;
  
  ctx.waitUntil(new Promise((resolve) => {
    server.addEventListener('close', () => { clearInterval(timer); resolve(); });
    server.addEventListener('error', () => { clearInterval(timer); resolve(); });
  }));
  
  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function drainQueueVLESS(server, state) {
  while (state.queue.length > 0) {
    const buffer = state.queue.shift();
    await processMessageVLESS(server, state, buffer);
  }
}

async function processMessageVLESS(server, state, buffer) {
  if (!state.connected) {
    // Parse header VLESS
    const { address, port, rawDataIndex } = parseVLESSHeader(buffer);
    
    // Connect ke target
    state.tcpSocket = connect(
      { hostname: address, port: port },
      { allowHalfOpen: false }
    );
    state.writer = state.tcpSocket.writable.getWriter();
    state.connected = true;
    
    // Kirim sisa payload
    const binaryData = new Uint8Array(buffer);
    if (binaryData.byteLength > rawDataIndex) {
      const payload = binaryData.subarray(rawDataIndex);
      await state.writer.write(payload);
    }
    
    // Pipe balik dari target ke client
    state.tcpSocket.readable
      .pipeTo(new WritableStream({
        write(chunk) {
          if (server.readyState === 1) {
            server.send(chunk);
          } else {
            throw new Error('WebSocket closed');
          }
        },
        close() { 
          if (server.readyState === 1) {
            server.close(1000, 'Done');
          }
        },
        abort(err) { 
          console.error('Pipe abort:', err);
          if (server.readyState === 1) {
            server.close(1000, 'Aborted');
          }
        },
      }))
      .catch(() => safeClose(server));
      
  } else {
    // Kirim data lanjutan
    const dataToWrite = buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    await state.writer.write(dataToWrite);
  }
}

// ==================== HANDLER TROJAN ====================
function handleTrojan(request, ctx) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  
  // KRUSIAL: Set binaryType dan allowHalfOpen
  server.binaryType = "arraybuffer";
  server.accept({ allowHalfOpen: true });
  
  const state = {
    tcpSocket: null,
    writer: null,
    connected: false,
    queue: [],
    processing: false,
  };
  
  server.addEventListener('message', async (event) => {
    try {
      let buf = event.data;
      if (buf instanceof Blob) {
        buf = await buf.arrayBuffer();
      } else if (!(buf instanceof ArrayBuffer)) {
        buf = buf.buffer?.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) ?? buf;
      }
      
      state.queue.push(buf);
      if (!state.processing) {
        state.processing = true;
        await drainQueueTrojan(server, state).catch(() => cleanup(state));
        state.processing = false;
      }
    } catch (err) {
      console.error('Message error:', err);
      cleanup(state);
    }
  });
  
  server.addEventListener('close', () => {
    clearKeepAlive(state);
    cleanup(state);
  });
  
  server.addEventListener('error', () => {
    clearKeepAlive(state);
    cleanup(state);
  });
  
  // Keep-alive: 30 detik
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
  }, 30000);
  
  state.keepAliveTimer = timer;
  
  ctx.waitUntil(new Promise((resolve) => {
    server.addEventListener('close', () => { clearInterval(timer); resolve(); });
    server.addEventListener('error', () => { clearInterval(timer); resolve(); });
  }));
  
  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function drainQueueTrojan(server, state) {
  while (state.queue.length > 0) {
    const buffer = state.queue.shift();
    await processMessageTrojan(server, state, buffer);
  }
}

async function processMessageTrojan(server, state, buffer) {
  if (!state.connected) {
    // Parse header Trojan
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
    
    state.tcpSocket.readable
      .pipeTo(new WritableStream({
        write(chunk) {
          if (server.readyState === 1) {
            server.send(chunk);
          } else {
            throw new Error('WebSocket closed');
          }
        },
        close() { 
          if (server.readyState === 1) {
            server.close(1000, 'Done');
          }
        },
        abort(err) { 
          console.error('Pipe abort:', err);
          if (server.readyState === 1) {
            server.close(1000, 'Aborted');
          }
        },
      }))
      .catch(() => safeClose(server));
      
  } else {
    const dataToWrite = buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    await state.writer.write(dataToWrite);
  }
}

// ==================== PARSER VLESS ====================
function parseVLESSHeader(buffer) {
  if (!(buffer instanceof ArrayBuffer)) {
    buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }
  
  if (buffer.byteLength < 42) throw new Error('Header VLESS terlalu pendek: ' + buffer.byteLength);
  
  const view = new DataView(buffer);
  
  // Versi (harus 0)
  const version = view.getUint8(0);
  if (version !== 0) throw new Error('Versi VLESS tidak valid: ' + version);
  
  // Validasi UUID (16 byte pertama setelah version, opsional)
  // Byte 17 = command (1=TCP, 2=UDP)
  const command = view.getUint8(17);
  if (command !== 1 && command !== 2) {
    throw new Error('Command tidak valid: ' + command);
  }
  
  // Port (byte 18-19)
  const port = view.getUint16(18);
  if (port === 0 || port > 65535) throw new Error('Port tidak valid: ' + port);
  
  // Address type di byte 20
  const addressType = view.getUint8(20);
  
  const { address, nextIndex } = readVLESSAddress(view, buffer, 21, addressType);
  
  let rawDataIndex = nextIndex;
  // Skip CRLF jika ada (tidak semua client mengirim CRLF)
  if (rawDataIndex + 2 <= buffer.byteLength) {
    const cr = view.getUint8(rawDataIndex);
    const lf = view.getUint8(rawDataIndex + 1);
    if (cr === 0x0d && lf === 0x0a) {
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
  
  throw new Error('Tipe alamat tidak didukung: ' + addressType);
}

// ==================== PARSER TROJAN ====================
function parseTrojanHeader(buffer) {
  if (!(buffer instanceof ArrayBuffer)) {
    buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }
  
  if (buffer.byteLength < 62) throw new Error('Header Trojan terlalu pendek: ' + buffer.byteLength);
  
  const view = new DataView(buffer);
  
  // Validasi CRLF di byte 56-57 (signature Trojan)
  const cr = view.getUint8(56);
  const lf = view.getUint8(57);
  if (cr !== 0x0d || lf !== 0x0a) {
    throw new Error('Koneksi ditolak: Bukan protokol Trojan valid');
  }
  
  // Port di byte 59-60
  const port = view.getUint16(59);
  if (port === 0 || port > 65535) throw new Error('Port tidak valid: ' + port);
  
  // Address type di byte 61
  const addrTypeIndex = 61;
  const addressType = view.getUint8(addrTypeIndex);
  
  const { address, nextIndex } = readTrojanAddress(view, buffer, addrTypeIndex + 1, addressType);
  
  let rawDataIndex = nextIndex;
  // Skip CRLF setelah address
  if (rawDataIndex + 2 <= buffer.byteLength) {
    const cr2 = view.getUint8(rawDataIndex);
    const lf2 = view.getUint8(rawDataIndex + 1);
    if (cr2 === 0x0d && lf2 === 0x0a) {
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
    for (let i = 0; i < 8; i++) {
      parts.push(view.getUint16(startIndex + i * 2).toString(16));
    }
    return { address: parts.join(':'), nextIndex: startIndex + 16 };
  }
  
  throw new Error('Tipe alamat tidak didukung: ' + addressType);
}

// ==================== UTILITY FUNCTIONS ====================
function cleanup(state) {
  try {
    if (state.writer) {
      state.writer.releaseLock();
    }
  } catch {}
  try {
    if (state.tcpSocket) {
      state.tcpSocket.close();
    }
  } catch {}
  state.writer = null;
  state.tcpSocket = null;
  state.connected = false;
}

function clearKeepAlive(state) {
  if (state.keepAliveTimer) {
    clearInterval(state.keepAliveTimer);
    state.keepAliveTimer = null;
  }
}

function safeClose(ws) {
  try {
    if (ws.readyState === 1) { // OPEN
      ws.close(1000, 'done');
    }
  } catch {}
}