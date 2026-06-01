import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');

    // 1. JALUR EKSPRES: Jika ada request WS atau HTTP Upgrade, langsung jalankan pipa data
    if (upgradeHeader === 'websocket' || url.searchParams.get('type') === 'httpupgrade') {
      return await handleTunnel(request, ctx);
    }

    // 2. HALAMAN LANDING PALSU (Agar DPI Operator Mengira Ini Web Biasa)
    return new Response('<html><body><h1>Service Ready</h1></body></html>', {
      status: 200,
      headers: { 'Content-Type': 'text/html' },
    });
  }
};

// PENANGANAN UTAMA PIPA DATA (VLESS & TROJAN)
async function handleTunnel(request, ctx) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);

  server.accept();

  // Pengganti event.waitUntil pada format ES Modules adalah ctx.waitUntil ( EOF Fix )
  ctx.waitUntil(handleDataStream(server));

  // Mengembalikan status HTTP 101 untuk menembus jabat tangan HTTP Upgrade / WS Xray
  return new Response(null, { 
    status: 101, 
    statusText: 'Switching Protocols',
    webSocket: client 
  });
}

async function handleDataStream(server) {
  let tcpSocket = null;
  let writer = null;

  server.addEventListener('message', async (event) => {
    const buffer = event.data;

    // JALUR AWAL: Membaca header paket pertama dari HP untuk mencari IP/Port VPS
    if (!tcpSocket) {
      try {
        const { address, port, rawDataIndex } = parseFastHeader(buffer);
        
        // Menghubungkan langsung socket TCP murni Cloudflare ke VPS
        tcpSocket = connect({ hostname: address, port: port });
        writer = tcpSocket.writable.getWriter();

        // Kirim sisa payload data pertama (Early Data) setelah header proxy dipotong
        if (buffer.byteLength > rawDataIndex) {
          const firstPayload = buffer.slice(rawDataIndex);
          await writer.write(firstPayload);
        }

        // PIPA DOWNSTREAM: Dari VPS diteruskan kembali ke Klien HP
        tcpSocket.readable.pipeTo(new WritableStream({
          write(chunk) {
            if (server.readyState === 1) { // 1 artinya WebSocket.OPEN
              server.send(chunk);
            }
          },
          close() { server.close(); },
          abort() { server.close(); }
        })).catch(() => server.close());

      } catch (err) {
        server.close();
        if (tcpSocket) tcpSocket.close();
      }
    } else {
      // JALUR EKSPRES (ZERO-COPY): Data berikutnya langsung dilempar ke VPS tanpa inspeksi (CPU < 2ms)
      try {
        await writer.write(buffer);
      } catch (e) {
        server.close();
      }
    }
  });

  server.addEventListener('close', () => { if (tcpSocket) tcpSocket.close(); });
  server.addEventListener('error', () => { if (tcpSocket) tcpSocket.close(); });
}

// PARSING ULTRA CEPAT (Mendukung VLESS & Trojan Secara Dinamis)
function parseFastHeader(buffer) {
  const view = new DataView(buffer);
  
  // Deteksi dinamis antara VLESS (UUID) atau Trojan (Hash/CRLF)
  let isVless = (buffer.byteLength >= 20 && view.getUint8(1) === 0);
  let addressTypeIndex = isVless ? 22 : 58; 
  
  if (buffer.byteLength < addressTypeIndex) {
    throw new Error("Header data terlalu pendek");
  }

  let addressType = view.getUint8(addressTypeIndex);
  let portIndex = addressTypeIndex + 1;
  let addressIndex = portIndex + 2;
  let port = view.getUint16(portIndex);
  let address = "";

  if (addressType === 1) { // IPv4
    address = new Uint8Array(buffer.slice(addressIndex, addressIndex + 4)).join('.');
    addressIndex += 4;
  } else if (addressType === 3) { // Domain Name
    const domainLength = view.getUint8(addressIndex);
    address = new TextDecoder().decode(buffer.slice(addressIndex + 1, addressIndex + 1 + domainLength));
    addressIndex += 1 + domainLength;
  } else {
    address = "127.0.0.1"; // Fallback aman
  }

  return { address, port, rawDataIndex: addressIndex };
}
