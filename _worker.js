import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');

    if (upgradeHeader === 'websocket' || url.searchParams.get('type') === 'httpupgrade') {
      return handleTunnel(request, ctx);
    }

    return new Response('<html><body><h1>Service Ready</h1></body></html>', {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
    });
  }
};

function handleTunnel(request, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);
  server.accept();

  ctx.waitUntil(handleDataStream(server));

  return new Response(null, {
    status: 101,
    statusText: 'Switching Protocols',
    webSocket: client,
  });
}

async function handleDataStream(server) {
  let tcpSocket = null;
  let writer = null;
  let isConnected = false;

  // Antrian pesan untuk menghindari race condition
  const messageQueue = [];
  let processing = false;

  async function processQueue() {
    if (processing) return;
    processing = true;

    while (messageQueue.length > 0) {
      const buffer = messageQueue.shift();
      try {
        await processMessage(buffer);
      } catch (err) {
        cleanup();
        break;
      }
    }

    processing = false;
  }

  async function processMessage(buffer) {
    if (!isConnected) {
      // Parsing header pertama
      const { address, port, rawDataIndex } = parseFastHeader(buffer);

      tcpSocket = connect(
        { hostname: address, port: port },
        { allowHalfOpen: false, secureTransport: 'off' }
      );

      writer = tcpSocket.writable.getWriter();
      isConnected = true;

      // Kirim early data jika ada
      if (buffer.byteLength > rawDataIndex) {
        await writer.write(new Uint8Array(buffer.slice(rawDataIndex)));
      }

      // Pipe downstream: VPS → Client
      tcpSocket.readable
        .pipeTo(
          new WritableStream({
            write(chunk) {
              try {
                if (server.readyState === WebSocket.OPEN) {
                  server.send(chunk);
                }
              } catch (_) {
                // Client disconnect, biarkan pipeTo throw supaya stream tutup rapi
                throw new Error('client closed');
              }
            },
            close() {
              safeClose(server);
            },
            abort(reason) {
              safeClose(server);
            },
          })
        )
        .catch(() => cleanup());

    } else {
      // Data berikutnya: langsung kirim ke VPS
      if (writer) {
        await writer.write(
          buffer instanceof ArrayBuffer
            ? new Uint8Array(buffer)
            : buffer
        );
      }
    }
  }

  function cleanup() {
    safeClose(server);
    if (writer) {
      writer.releaseLock();
      writer = null;
    }
    if (tcpSocket) {
      try { tcpSocket.close(); } catch (_) {}
      tcpSocket = null;
    }
    isConnected = false;
  }

  server.addEventListener('message', (event) => {
    messageQueue.push(event.data);
    processQueue().catch(cleanup);
  });

  server.addEventListener('close', cleanup);
  server.addEventListener('error', cleanup);

  // Keepalive ping setiap 25 detik untuk mencegah idle timeout Cloudflare
  const pingInterval = setInterval(() => {
    try {
      if (server.readyState === WebSocket.OPEN) {
        server.send(new Uint8Array(0)); // ping kosong
      } else {
        clearInterval(pingInterval);
      }
    } catch (_) {
      clearInterval(pingInterval);
    }
  }, 25000);
}

function safeClose(ws) {
  try {
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close(1000, 'done');
    }
  } catch (_) {}
}

// Parser header VLESS & Trojan
function parseFastHeader(buffer) {
  if (buffer instanceof ArrayBuffer === false) {
    buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }

  const view = new DataView(buffer);

  if (buffer.byteLength < 20) {
    throw new Error('Header terlalu pendek');
  }

  // Deteksi VLESS: byte ke-1 adalah 0 (version 0)
  const isVless = view.getUint8(0) === 0 && buffer.byteLength >= 24;

  let addressTypeIndex;

  if (isVless) {
    // Format VLESS: [1 ver][16 uuid][1 addons_len][addons][1 cmd][2 port][1 atype]...
    const addonsLen = view.getUint8(17);
    addressTypeIndex = 18 + addonsLen + 1 + 2; // skip cmd(1) + port(2) → tapi kita baca port dulu
    const portIndex = 18 + addonsLen + 1;
    const port = view.getUint16(portIndex);
    addressTypeIndex = portIndex + 2;
    const addressType = view.getUint8(addressTypeIndex);
    const { address, nextIndex } = readAddress(view, buffer, addressTypeIndex + 1, addressType);
    return { address, port, rawDataIndex: nextIndex };

  } else {
    // Trojan: [56 hash][2 CRLF][1 cmd][2 port][1 atype]...
    // Minimal panjang: 56 + 2 + 1 + 2 + 1 = 62
    if (buffer.byteLength < 62) throw new Error('Header Trojan terlalu pendek');
    const portIndex = 59; // 56 hash + \r\n(2) + cmd(1) = 59
    const port = view.getUint16(portIndex);
    const addressTypeIndex = 61;
    const addressType = view.getUint8(addressTypeIndex);
    const { address, nextIndex } = readAddress(view, buffer, addressTypeIndex + 1, addressType);
    return { address, port, rawDataIndex: nextIndex };
  }
}

function readAddress(view, buffer, startIndex, addressType) {
  let address = '';
  let nextIndex = startIndex;

  if (addressType === 1) {
    // IPv4 (4 byte)
    if (buffer.byteLength < startIndex + 4) throw new Error('IPv4 truncated');
    address = Array.from(new Uint8Array(buffer, startIndex, 4)).join('.');
    nextIndex = startIndex + 4;

  } else if (addressType === 3) {
    // Domain name
    const domainLen = view.getUint8(startIndex);
    if (buffer.byteLength < startIndex + 1 + domainLen) throw new Error('Domain truncated');
    address = new TextDecoder().decode(new Uint8Array(buffer, startIndex + 1, domainLen));
    nextIndex = startIndex + 1 + domainLen;

  } else if (addressType === 2) {
    // IPv6 (16 byte)
    if (buffer.byteLength < startIndex + 16) throw new Error('IPv6 truncated');
    const ipv6Parts = [];
    for (let i = 0; i < 8; i++) {
      ipv6Parts.push(view.getUint16(startIndex + i * 2).toString(16));
    }
    address = ipv6Parts.join(':');
    nextIndex = startIndex + 16;

  } else {
    throw new Error(`Tipe address tidak dikenal: ${addressType}`);
  }

  return { address, nextIndex };
}