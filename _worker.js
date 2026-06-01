import { connect } from "cloudflare:sockets";

export default {
  async fetch(request) {
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader === "websocket") {
      return await websocketHandler(request);
    }
    return new Response("Minimal VLESS & Trojan CF Worker", { status: 200 });
  }
};

async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocket = null;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (remoteSocket) {
            const writer = remoteSocket.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          let protocolHeader;
          if (isVless(chunk)) {
            protocolHeader = readVlessHeader(chunk);
          } else if (isTrojan(chunk)) {
            protocolHeader = readTrojanHeader(chunk);
          } else {
            throw new Error("Unknown Protocol");
          }

          if (protocolHeader.hasError) throw new Error("Header Error");

          // Menggunakan Cloudflare sebagai Outbound Proxy (Koneksi langsung ke Address Remote)
          remoteSocket = connect({ hostname: protocolHeader.addressRemote, port: protocolHeader.portRemote });
          
          const writer = remoteSocket.writable.getWriter();
          await writer.write(protocolHeader.rawClientData);
          writer.releaseLock();

          remoteSocketToWS(remoteSocket, webSocket, protocolHeader.version);
        },
        close() {},
        abort() {}
      })
    ).catch(() => {});

  return new Response(null, { status: 101, webSocket: client });
}

function isVless(buffer) {
  return buffer.byteLength >= 18 && new Uint8Array(buffer.slice(0, 1))[0] === 0;
}

function isTrojan(buffer) {
  if (buffer.byteLength >= 58) {
    const delim = new Uint8Array(buffer.slice(56, 58));
    return delim[0] === 0x0d && delim[1] === 0x0a;
  }
  return false;
}

function readVlessHeader(buffer) {
  try {
    const version = new Uint8Array(buffer.slice(0, 1));
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const portIndex = 18 + optLength + 1; // Lewati cmd (1 byte)
    const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);
    
    let addressIndex = portIndex + 2;
    const addressType = buffer[addressIndex];
    let addressLength = 0, addressValueIndex = addressIndex + 1, addressValue = "";

    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
        break;
      case 2: // Domain
        addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 3: // IPv6
        addressLength = 16;
        const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
        addressValue = ipv6.join(":");
        break;
    }
    return {
      hasError: false,
      addressRemote: addressValue,
      portRemote,
      rawClientData: buffer.slice(addressValueIndex + addressLength),
      version: new Uint8Array([version[0], 0])
    };
  } catch (e) {
    return { hasError: true };
  }
}

function readTrojanHeader(buffer) {
  try {
    const dataBuffer = buffer.slice(58);
    const view = new DataView(dataBuffer);
    let addressType = view.getUint8(1); // Lewati cmd (1 byte)
    let addressLength = 0, addressValueIndex = 2, addressValue = "";

    switch (addressType) {
      case 1: // IPv4
        addressLength = 4;
        addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
        break;
      case 3: // Domain
        addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      case 4: // IPv6
        addressLength = 16;
        const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
        addressValue = ipv6.join(":");
        break;
    }
    const portIndex = addressValueIndex + addressLength;
    const portRemote = new DataView(dataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

    return {
      hasError: false,
      addressRemote: addressValue,
      portRemote,
      rawClientData: dataBuffer.slice(portIndex + 4), // Lewati port (2 byte) + CRLF (2 byte)
      version: null
    };
  } catch (e) {
    return { hasError: true };
  }
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader) {
  let header = responseHeader;
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      async write(chunk) {
        if (webSocket.readyState !== 1) return;
        if (header) {
          webSocket.send(await new Blob([header, chunk]).arrayBuffer());
          header = null;
        } else {
          webSocket.send(chunk);
        }
      }
    })
  ).catch(() => {});
}

function makeReadableWebSocketStream(webSocket, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      webSocket.addEventListener("message", (event) => {
        controller.enqueue(event.data);
      });
      webSocket.addEventListener("close", () => controller.close());
      webSocket.addEventListener("error", (err) => controller.error(err));

      if (earlyDataHeader) {
        try {
          const decode = atob(earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/"));
          controller.enqueue(Uint8Array.from(decode, (c) => c.charCodeAt(0)).buffer);
        } catch (e) {}
      }
    }
  });
}
