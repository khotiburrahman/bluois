import { connect } from 'cloudflare:sockets';

// KONEKSI UTAMA & KONFIGURASI
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');

    // 1. VALIDASI JALUR TUNNEL (WS ATAU HTTP UPGRADE)
    if (upgradeHeader === 'websocket' || url.searchParams.get('type') === 'httpupgrade') {
      return await handleTunnel(request);
    }

    // 2. HALAMAN LANDING PALSU (Agar Terlihat Seperti Web Biasa)
    return new Response('<html><body><h1>Welcome to My Web Service</h1></body></html>', {
      headers: { 'Content-Type': 'text/html' },
    });
  }
};

async function handleTunnel(request) {
  const webSocketPair = new WebSocketPair();
  const [client, server] = Object.values(webSocketPair);

  server.accept();

  let tcpSocket = null;
  let isEarlyData = true;

  // STREAM HANDLING (Sangat Ringan, Langsung Meneruskan Byte Mentah)
  server.addEventListener('message', async (event) => {
    const buffer = event.data;

    // Jika socket TCP ke VPS belum terbuka, bongkar header pertama kali
    if (!tcpSocket) {
      try {
        const { protocol, address, port, rawDataIndex } = parseHeader(buffer);
        
        // Hubungkan langsung ke VPS menggunakan Cloudflare Sockets
        tcpSocket = connect({ hostname: address, port: port });
        const writer = tcpSocket.writable.getWriter();

        // Kirim sisa data payload setelah header dibuang
        if (buffer.byteLength > rawDataIndex) {
          const remainingData = buffer.slice(rawDataIndex);
          await writer.write(remainingData);
        }

        // Pipa Otomatis: VPS -> Client
        tcpSocket.readable.pipeTo(new WritableStream({
          write(chunk) {
            if (server.readyState === WebSocket.OPEN) {
              server.send(chunk);
            }
          },
          close() { server.close(); },
          abort() { server.close(); }
        }));

        // Pipa Otomatis: Client -> VPS (Untuk paket data selanjutnya)
        isEarlyData = false;
        writer.releaseLock();
      } catch (err) {
        server.close();
      }
    } else {
      // Jalur Ekspres: Jika socket sudah ada, langsung lempar data tanpa diperiksa lagi (Menghemat CPU)
      const writer = tcpSocket.writable.getWriter();
      await writer.write(buffer);
      writer.releaseLock();
    }
  });

  server.addEventListener('close', () => { if (tcpSocket) tcpSocket.close(); });
  server.addEventListener('error', () => { if (tcpSocket) tcpSocket.close(); });

  return new Response(null, { status: 101, webSocket: client });
}

// PARSING HEADER (VLESS & TROJAN)
function parseHeader(buffer) {
  const view = new DataView(buffer);
  
  // Deteksi Protokol berdasarkan byte awal
  const firstByte = view.getUint8(0);
  
  let addressTypeIndex = 0;
  let addressType = 0;
  let isUDP = false;

  // Kondisi A: Kemungkinan VLESS (Menggunakan UUID versi panjang)
  if (buffer.byteLength >= 20 && view.getUint8(1) === 0) { 
    addressTypeIndex = 22; // Letak address type pada VLESS
    addressType = view.getUint8(addressTypeIndex);
  } else { 
    // Kondisi B: Trojan (Biasanya diawali CR LF atau password hash)
    addressTypeIndex = 58; // Estimasi standar Trojan over WS
    addressType = view.getUint8(addressTypeIndex);
  }

  // Ambil data Port dan Address Remote tujuan
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
  } else if (addressType === 2) { // IPv6
    addressIndex += 16; // Lewati pembacaan formal demi kecepatan
    address = "127.0.0.1"; 
  }

  return {
    address: address,
    port: port,
    rawDataIndex: addressIndex
  };
}
