import { connect } from 'cloudflare:sockets';

// ==================== LOGGING SYSTEM ====================
// Logger dengan berbagai level dan detail lengkap
const Logger = {
  // Konfigurasi
  config: {
    enabled: true,
    level: 'debug', // debug, info, warn, error
    showTimestamp: true,
    showStack: true
  },
  
  // Format timestamp
  timestamp() {
    return new Date().toISOString();
  },
  
  // Log dengan level DEBUG
  debug(context, data) {
    if (!this.config.enabled) return;
    if (this.config.level === 'debug') {
      console.log(JSON.stringify({
        level: 'DEBUG',
        timestamp: this.config.showTimestamp ? this.timestamp() : undefined,
        context: context,
        data: data,
        ...(data?.error && this.config.showStack ? { stack: data.error.stack } : {})
      }, null, 0));
    }
  },
  
  // Log dengan level INFO
  info(context, data) {
    if (!this.config.enabled) return;
    if (['debug', 'info'].includes(this.config.level)) {
      console.log(JSON.stringify({
        level: 'INFO',
        timestamp: this.config.showTimestamp ? this.timestamp() : undefined,
        context: context,
        data: data
      }, null, 0));
    }
  },
  
  // Log dengan level WARNING
  warn(context, data) {
    if (!this.config.enabled) return;
    if (['debug', 'info', 'warn'].includes(this.config.level)) {
      console.warn(JSON.stringify({
        level: 'WARN',
        timestamp: this.config.showTimestamp ? this.timestamp() : undefined,
        context: context,
        data: data,
        ...(data?.error && this.config.showStack ? { stack: data.error.stack } : {})
      }, null, 0));
    }
  },
  
  // Log dengan level ERROR (paling detail)
  error(context, error, additionalData = {}) {
    if (!this.config.enabled) return;
    
    const errorDetails = {
      level: 'ERROR',
      timestamp: this.config.showTimestamp ? this.timestamp() : undefined,
      context: context,
      error: {
        name: error?.name || 'UnknownError',
        message: error?.message || String(error),
        code: error?.code || null,
        cause: error?.cause ? String(error.cause) : null,
      },
      additionalData: additionalData
    };
    
    if (this.config.showStack && error?.stack) {
      errorDetails.stack = error.stack;
    }
    
    // Capture error location in code
    const stackLine = error?.stack?.split('\n')[1];
    if (stackLine) {
      errorDetails.location = stackLine.trim();
    }
    
    console.error(JSON.stringify(errorDetails, null, 0));
  },
  
  // Log state/snapshot untuk debugging
  snapshot(context, state) {
    if (!this.config.enabled) return;
    if (this.config.level === 'debug') {
      const snapshot = {
        level: 'SNAPSHOT',
        timestamp: this.config.showTimestamp ? this.timestamp() : undefined,
        context: context,
        state: {
          connected: state.connected,
          queueLength: state.queue?.length || 0,
          processing: state.processing,
          hasWriter: !!state.writer,
          hasSocket: !!state.tcpSocket,
          writerLocked: state.writer?.locked,
          socketReady: state.tcpSocket?.readyState,
          keepAliveTimer: !!state.keepAliveTimer
        }
      };
      console.log(JSON.stringify(snapshot, null, 0));
    }
  }
};

// ==================== MAIN HANDLER ====================
export default {
  async fetch(request, env, ctx) {
    const requestId = crypto.randomUUID();
    
    Logger.info('REQUEST_START', {
      requestId,
      url: request.url,
      method: request.method,
      headers: {
        upgrade: request.headers.get('Upgrade'),
        userAgent: request.headers.get('User-Agent'),
        connection: request.headers.get('Connection')
      },
      cf: request.cf
    });
    
    try {
      const upgradeHeader = request.headers.get('Upgrade');
      const url = new URL(request.url);
      
      // Log semua path yang diakses
      Logger.debug('REQUEST_PATH', { requestId, pathname: url.pathname, search: url.search });
      
      // Handle WebSocket upgrade
      if (upgradeHeader === 'websocket' || upgradeHeader === 'httpupgrade') {
        Logger.info('WEBSOCKET_UPGRADE', { requestId, protocol: upgradeHeader, path: url.pathname });
        
        if (url.pathname === '/vless') {
          Logger.info('ROUTE_VLESS', { requestId });
          return handleVLESS(request, ctx, requestId);
        } 
        
        if (url.pathname === '/trojan') {
          Logger.info('ROUTE_TROJAN', { requestId });
          return handleTrojan(request, ctx, requestId);
        }
        
        Logger.warn('UNKNOWN_PATH', { requestId, pathname: url.pathname });
        return handleTrojan(request, ctx, requestId);
      }
      
      // Response untuk HTTP request biasa
      Logger.info('HTTP_RESPONSE', { requestId, type: 'info_page' });
      return new Response(`<html>
<body>
<h1>Proxy Tunnel Ready</h1>
<p>Request ID: ${requestId}</p>
<p>Gunakan endpoint:</p>
<ul>
<li>VLESS: wss://${url.hostname}/vless</li>
<li>Trojan: wss://${url.hostname}/trojan</li>
</ul>
<p>Status: RUNNING</p>
</body>
</html>`, {
        status: 200,
        headers: { 
          'Content-Type': 'text/html',
          'X-Request-Id': requestId
        },
      });
      
    } catch (error) {
      Logger.error('FETCH_HANDLER_CRASH', error, { requestId, url: request.url });
      return new Response(`Internal Server Error\nRequest ID: ${requestId}`, { 
        status: 500,
        headers: { 'X-Request-Id': requestId }
      });
    }
  }
};

// ==================== HANDLER VLESS ====================
function handleVLESS(request, ctx, requestId) {
  Logger.debug('VLESS_HANDLER_ENTER', { requestId });
  
  try {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    
    // Konfigurasi WebSocket
    server.binaryType = "arraybuffer";
    
    try {
      server.accept({ allowHalfOpen: true });
      Logger.debug('VLESS_WS_ACCEPTED', { requestId, binaryType: server.binaryType });
    } catch (error) {
      Logger.error('VLESS_WS_ACCEPT_FAILED', error, { requestId });
      throw error;
    }
    
    const state = {
      requestId: requestId,
      tcpSocket: null,
      writer: null,
      connected: false,
      queue: [],
      processing: false,
      keepAliveTimer: null,
      bytesReceived: 0,
      bytesSent: 0,
      startTime: Date.now()
    };
    
    // WebSocket message handler
    server.addEventListener('message', async (event) => {
      const messageId = crypto.randomUUID();
      Logger.debug('VLESS_WS_MESSAGE_RECEIVED', { 
        requestId, 
        messageId,
        dataType: typeof event.data,
        isBlob: event.data instanceof Blob,
        isArrayBuffer: event.data instanceof ArrayBuffer,
        size: event.data?.byteLength || event.data?.size || 0
      });
      
      try {
        let buf;
        if (event.data instanceof Blob) {
          buf = await event.data.arrayBuffer();
          Logger.debug('VLESS_BLOB_CONVERTED', { requestId, messageId, size: buf.byteLength });
        } else if (event.data instanceof ArrayBuffer) {
          buf = event.data;
        } else if (event.data.buffer instanceof ArrayBuffer) {
          buf = event.data.buffer.slice(event.data.byteOffset, event.data.byteOffset + event.data.byteLength);
        } else {
          Logger.warn('VLESS_UNKNOWN_DATA_TYPE', { requestId, messageId, type: typeof event.data });
          buf = new Uint8Array(0).buffer;
        }
        
        state.bytesReceived += buf.byteLength;
        state.queue.push(buf);
        
        if (!state.processing) {
          state.processing = true;
          await drainQueueVLESS(server, state).catch(error => {
            Logger.error('VLESS_DRAIN_QUEUE_ERROR', error, { requestId, messageId });
            cleanup(state);
          });
          state.processing = false;
        }
      } catch (error) {
        Logger.error('VLESS_MESSAGE_PROCESSING_ERROR', error, { 
          requestId, 
          messageId,
          queueLength: state.queue.length,
          connected: state.connected
        });
        cleanup(state);
      }
    });
    
    // WebSocket close handler
    server.addEventListener('close', (event) => {
      const duration = Date.now() - state.startTime;
      Logger.info('VLESS_WS_CLOSED', {
        requestId,
        code: event.code,
        reason: event.reason,
        wasClean: event.wasClean,
        duration: `${duration}ms`,
        bytesReceived: state.bytesReceived,
        bytesSent: state.bytesSent,
        connected: state.connected
      });
      cleanup(state);
    });
    
    // WebSocket error handler
    server.addEventListener('error', (error) => {
      Logger.error('VLESS_WS_ERROR', error, {
        requestId,
        readyState: server.readyState,
        connected: state.connected
      });
      cleanup(state);
    });
    
    // Keep-alive ping
    const timer = setInterval(() => {
      try {
        if (server.readyState === 1) { // OPEN
          server.send(new Uint8Array(0));
          Logger.debug('VLESS_PING_SENT', { requestId });
        } else {
          Logger.debug('VLESS_PING_SKIPPED', { requestId, readyState: server.readyState });
          clearInterval(timer);
        }
      } catch (error) {
        Logger.error('VLESS_PING_ERROR', error, { requestId });
        clearInterval(timer);
      }
    }, 30000);
    
    state.keepAliveTimer = timer;
    
    // Cleanup on context waitUntil
    ctx.waitUntil(new Promise((resolve) => {
      server.addEventListener('close', () => {
        clearInterval(timer);
        resolve();
      });
      server.addEventListener('error', () => {
        clearInterval(timer);
        resolve();
      });
    }));
    
    Logger.info('VLESS_HANDLER_SUCCESS', { requestId });
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { 'X-Request-Id': requestId }
    });
    
  } catch (error) {
    Logger.error('VLESS_HANDLER_FATAL', error, { requestId });
    return new Response(`WebSocket upgrade failed\nRequest ID: ${requestId}`, { status: 500 });
  }
}

async function drainQueueVLESS(server, state) {
  while (state.queue.length > 0) {
    const buffer = state.queue.shift();
    await processMessageVLESS(server, state, buffer);
  }
}

async function processMessageVLESS(server, state, buffer) {
  const { requestId } = state;
  
  if (!state.connected) {
    // First message - parse header and connect
    Logger.debug('VLESS_FIRST_MESSAGE', { 
      requestId, 
      bufferSize: buffer.byteLength,
      timestamp: Date.now()
    });
    
    try {
      // Parse header
      Logger.debug('VLESS_PARSE_START', { requestId });
      const { address, port, rawDataIndex, uuid, command } = parseVLESSHeader(buffer);
      Logger.info('VLESS_PARSE_SUCCESS', {
        requestId,
        address,
        port,
        rawDataIndex,
        uuid: uuid?.substring(0, 8) + '...', // Log partial UUID only
        command: command === 1 ? 'TCP' : 'UDP'
      });
      
      // Connect to target
      Logger.debug('VLESS_CONNECTING', { requestId, address, port });
      
      let tcpSocket;
      try {
        tcpSocket = connect(
          { hostname: address, port: port },
          { allowHalfOpen: false }
        );
        Logger.info('VLESS_CONNECTED', { requestId, address, port });
      } catch (error) {
        Logger.error('VLESS_CONNECT_FAILED', error, { requestId, address, port });
        throw error;
      }
      
      state.tcpSocket = tcpSocket;
      state.writer = tcpSocket.writable.getWriter();
      state.connected = true;
      
      // Send remaining payload
      const binaryData = new Uint8Array(buffer);
      if (binaryData.byteLength > rawDataIndex) {
        const payload = binaryData.subarray(rawDataIndex);
        Logger.debug('VLESS_SENDING_INITIAL_PAYLOAD', { 
          requestId, 
          payloadSize: payload.byteLength 
        });
        await state.writer.write(payload);
        state.bytesSent += payload.byteLength;
      }
      
      // Pipe data from target to client
      Logger.debug('VLESS_PIPE_START', { requestId });
      state.tcpSocket.readable
        .pipeTo(new WritableStream({
          write(chunk) {
            if (server.readyState === 1) {
              server.send(chunk);
              state.bytesSent += chunk.byteLength;
              Logger.debug('VLESS_PIPE_DATA_SENT', { 
                requestId, 
                chunkSize: chunk.byteLength,
                totalSent: state.bytesSent 
              });
            } else {
              Logger.warn('VLESS_PIPE_WS_CLOSED', { 
                requestId, 
                readyState: server.readyState 
              });
              throw new Error('WebSocket closed');
            }
          },
          close() {
            Logger.info('VLESS_PIPE_CLOSED', { 
              requestId, 
              bytesSent: state.bytesSent 
            });
            safeClose(server);
          },
          abort(error) {
            Logger.error('VLESS_PIPE_ABORTED', error, { 
              requestId, 
              bytesSent: state.bytesSent 
            });
            safeClose(server);
          }
        }))
        .catch(error => {
          Logger.error('VLESS_PIPE_ERROR', error, { requestId });
          safeClose(server);
        });
        
    } catch (error) {
      Logger.error('VLESS_PROCESS_FIRST_MESSAGE', error, { 
        requestId, 
        bufferSize: buffer.byteLength 
      });
      cleanup(state);
      safeClose(server);
      throw error;
    }
    
  } else {
    // Subsequent messages - just forward data
    try {
      const dataToWrite = buffer instanceof ArrayBuffer
        ? new Uint8Array(buffer)
        : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      
      await state.writer.write(dataToWrite);
      state.bytesSent += dataToWrite.byteLength;
      
      Logger.debug('VLESS_DATA_FORWARDED', { 
        requestId, 
        size: dataToWrite.byteLength,
        totalSent: state.bytesSent 
      });
    } catch (error) {
      Logger.error('VLESS_FORWARD_ERROR', error, { 
        requestId, 
        bufferSize: buffer?.byteLength 
      });
      throw error;
    }
  }
}

// ==================== HANDLER TROJAN ====================
function handleTrojan(request, ctx, requestId) {
  Logger.debug('TROJAN_HANDLER_ENTER', { requestId });
  
  try {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    
    server.binaryType = "arraybuffer";
    
    try {
      server.accept({ allowHalfOpen: true });
      Logger.debug('TROJAN_WS_ACCEPTED', { requestId });
    } catch (error) {
      Logger.error('TROJAN_WS_ACCEPT_FAILED', error, { requestId });
      throw error;
    }
    
    const state = {
      requestId: requestId,
      tcpSocket: null,
      writer: null,
      connected: false,
      queue: [],
      processing: false,
      keepAliveTimer: null,
      bytesReceived: 0,
      bytesSent: 0,
      startTime: Date.now()
    };
    
    server.addEventListener('message', async (event) => {
      const messageId = crypto.randomUUID();
      Logger.debug('TROJAN_WS_MESSAGE_RECEIVED', { 
        requestId, 
        messageId,
        dataType: typeof event.data,
        size: event.data?.byteLength || event.data?.size || 0
      });
      
      try {
        let buf;
        if (event.data instanceof Blob) {
          buf = await event.data.arrayBuffer();
        } else if (event.data instanceof ArrayBuffer) {
          buf = event.data;
        } else if (event.data.buffer instanceof ArrayBuffer) {
          buf = event.data.buffer.slice(event.data.byteOffset, event.data.byteOffset + event.data.byteLength);
        } else {
          Logger.warn('TROJAN_UNKNOWN_DATA_TYPE', { requestId, messageId, type: typeof event.data });
          buf = new Uint8Array(0).buffer;
        }
        
        state.bytesReceived += buf.byteLength;
        state.queue.push(buf);
        
        if (!state.processing) {
          state.processing = true;
          await drainQueueTrojan(server, state).catch(error => {
            Logger.error('TROJAN_DRAIN_QUEUE_ERROR', error, { requestId, messageId });
            cleanup(state);
          });
          state.processing = false;
        }
      } catch (error) {
        Logger.error('TROJAN_MESSAGE_PROCESSING_ERROR', error, { requestId, messageId });
        cleanup(state);
      }
    });
    
    server.addEventListener('close', (event) => {
      const duration = Date.now() - state.startTime;
      Logger.info('TROJAN_WS_CLOSED', {
        requestId,
        code: event.code,
        reason: event.reason,
        wasClean: event.wasClean,
        duration: `${duration}ms`,
        bytesReceived: state.bytesReceived,
        bytesSent: state.bytesSent
      });
      cleanup(state);
    });
    
    server.addEventListener('error', (error) => {
      Logger.error('TROJAN_WS_ERROR', error, { requestId, readyState: server.readyState });
      cleanup(state);
    });
    
    const timer = setInterval(() => {
      try {
        if (server.readyState === 1) {
          server.send(new Uint8Array(0));
          Logger.debug('TROJAN_PING_SENT', { requestId });
        } else {
          clearInterval(timer);
        }
      } catch (error) {
        Logger.error('TROJAN_PING_ERROR', error, { requestId });
        clearInterval(timer);
      }
    }, 30000);
    
    state.keepAliveTimer = timer;
    
    ctx.waitUntil(new Promise((resolve) => {
      server.addEventListener('close', () => { clearInterval(timer); resolve(); });
      server.addEventListener('error', () => { clearInterval(timer); resolve(); });
    }));
    
    Logger.info('TROJAN_HANDLER_SUCCESS', { requestId });
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { 'X-Request-Id': requestId }
    });
    
  } catch (error) {
    Logger.error('TROJAN_HANDLER_FATAL', error, { requestId });
    return new Response(`WebSocket upgrade failed\nRequest ID: ${requestId}`, { status: 500 });
  }
}

async function drainQueueTrojan(server, state) {
  while (state.queue.length > 0) {
    const buffer = state.queue.shift();
    await processMessageTrojan(server, state, buffer);
  }
}

async function processMessageTrojan(server, state, buffer) {
  const { requestId } = state;
  
  if (!state.connected) {
    Logger.debug('TROJAN_FIRST_MESSAGE', { requestId, bufferSize: buffer.byteLength });
    
    try {
      const { address, port, rawDataIndex } = parseTrojanHeader(buffer);
      Logger.info('TROJAN_PARSE_SUCCESS', { requestId, address, port, rawDataIndex });
      
      Logger.debug('TROJAN_CONNECTING', { requestId, address, port });
      
      let tcpSocket;
      try {
        tcpSocket = connect(
          { hostname: address, port: port },
          { allowHalfOpen: false }
        );
        Logger.info('TROJAN_CONNECTED', { requestId, address, port });
      } catch (error) {
        Logger.error('TROJAN_CONNECT_FAILED', error, { requestId, address, port });
        throw error;
      }
      
      state.tcpSocket = tcpSocket;
      state.writer = tcpSocket.writable.getWriter();
      state.connected = true;
      
      const binaryData = new Uint8Array(buffer);
      if (binaryData.byteLength > rawDataIndex) {
        const payload = binaryData.subarray(rawDataIndex);
        Logger.debug('TROJAN_SENDING_INITIAL_PAYLOAD', { requestId, payloadSize: payload.byteLength });
        await state.writer.write(payload);
        state.bytesSent += payload.byteLength;
      }
      
      Logger.debug('TROJAN_PIPE_START', { requestId });
      state.tcpSocket.readable
        .pipeTo(new WritableStream({
          write(chunk) {
            if (server.readyState === 1) {
              server.send(chunk);
              state.bytesSent += chunk.byteLength;
            } else {
              throw new Error('WebSocket closed');
            }
          },
          close() {
            Logger.info('TROJAN_PIPE_CLOSED', { requestId, bytesSent: state.bytesSent });
            safeClose(server);
          },
          abort(error) {
            Logger.error('TROJAN_PIPE_ABORTED', error, { requestId });
            safeClose(server);
          }
        }))
        .catch(error => {
          Logger.error('TROJAN_PIPE_ERROR', error, { requestId });
          safeClose(server);
        });
        
    } catch (error) {
      Logger.error('TROJAN_PROCESS_FIRST_MESSAGE', error, { requestId, bufferSize: buffer.byteLength });
      cleanup(state);
      safeClose(server);
      throw error;
    }
    
  } else {
    try {
      const dataToWrite = buffer instanceof ArrayBuffer
        ? new Uint8Array(buffer)
        : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      
      await state.writer.write(dataToWrite);
      state.bytesSent += dataToWrite.byteLength;
      
      Logger.debug('TROJAN_DATA_FORWARDED', { 
        requestId, 
        size: dataToWrite.byteLength,
        totalSent: state.bytesSent 
      });
    } catch (error) {
      Logger.error('TROJAN_FORWARD_ERROR', error, { requestId });
      throw error;
    }
  }
}

// ==================== PARSER VLESS ====================
function parseVLESSHeader(buffer) {
  try {
    // Ensure buffer is ArrayBuffer
    if (!(buffer instanceof ArrayBuffer)) {
      buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
    }
    
    if (buffer.byteLength < 42) {
      throw new Error(`Header VLESS terlalu pendek: ${buffer.byteLength} bytes (minimal 42 bytes)`);
    }
    
    const view = new DataView(buffer);
    
    // Parse version (byte 0)
    const version = view.getUint8(0);
    if (version !== 0) {
      throw new Error(`Versi VLESS tidak valid: ${version} (harus 0)`);
    }
    
    // Parse UUID (bytes 1-16) - optional untuk logging
    const uuidBytes = new Uint8Array(buffer, 1, 16);
    const uuid = Array.from(uuidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const formattedUUID = `${uuid.slice(0,8)}-${uuid.slice(8,12)}-${uuid.slice(12,16)}-${uuid.slice(16,20)}-${uuid.slice(20,32)}`;
    
    // Parse command (byte 17)
    const command = view.getUint8(17);
    if (command !== 1 && command !== 2) {
      throw new Error(`Command tidak valid: ${command} (harus 1 untuk TCP atau 2 untuk UDP)`);
    }
    
    // Parse port (bytes 18-19)
    const port = view.getUint16(18);
    if (port === 0 || port > 65535) {
      throw new Error(`Port tidak valid: ${port}`);
    }
    
    // Parse address type (byte 20)
    const addressType = view.getUint8(20);
    let address, nextIndex;
    
    if (addressType === 1) { // IPv4
      if (buffer.byteLength < 21 + 4) {
        throw new Error(`IPv4 address terpotong: need 4 bytes, have ${buffer.byteLength - 21}`);
      }
      address = Array.from(new Uint8Array(buffer, 21, 4)).join('.');
      nextIndex = 21 + 4;
      Logger.debug('VLESS_PARSE_IPV4', { address, nextIndex });
      
    } else if (addressType === 3) { // Domain name
      const domainLen = view.getUint8(21);
      if (buffer.byteLength < 22 + domainLen) {
        throw new Error(`Domain name terpotong: need ${domainLen} bytes, have ${buffer.byteLength - 22}`);
      }
      address = new TextDecoder().decode(new Uint8Array(buffer, 22, domainLen));
      nextIndex = 22 + domainLen;
      Logger.debug('VLESS_PARSE_DOMAIN', { address, domainLen, nextIndex });
      
    } else if (addressType === 2) { // IPv6
      if (buffer.byteLength < 21 + 16) {
        throw new Error(`IPv6 address terpotong: need 16 bytes, have ${buffer.byteLength - 21}`);
      }
      const parts = [];
      for (let i = 0; i < 8; i++) {
        parts.push(view.getUint16(21 + i * 2).toString(16));
      }
      address = parts.join(':');
      nextIndex = 21 + 16;
      Logger.debug('VLESS_PARSE_IPV6', { address, nextIndex });
      
    } else {
      throw new Error(`Tipe alamat tidak didukung: ${addressType} (1=IPv4, 2=IPv6, 3=Domain)`);
    }
    
    // Find CRLF if exists
    let rawDataIndex = nextIndex;
    if (rawDataIndex + 2 <= buffer.byteLength) {
      const cr = view.getUint8(rawDataIndex);
      const lf = view.getUint8(rawDataIndex + 1);
      if (cr === 0x0d && lf === 0x0a) {
        rawDataIndex += 2;
        Logger.debug('VLESS_CRLF_FOUND', { rawDataIndex });
      }
    }
    
    return { address, port, rawDataIndex, uuid: formattedUUID, command };
    
  } catch (error) {
    Logger.error('VLESS_PARSE_ERROR', error, { bufferSize: buffer?.byteLength });
    throw error;
  }
}

// ==================== PARSER TROJAN ====================
function parseTrojanHeader(buffer) {
  try {
    if (!(buffer instanceof ArrayBuffer)) {
      buffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
    }
    
    if (buffer.byteLength < 62) {
      throw new Error(`Header Trojan terlalu pendek: ${buffer.byteLength} bytes (minimal 62 bytes)`);
    }
    
    const view = new DataView(buffer);
    
    // Validate CRLF at bytes 56-57 (Trojan signature)
    const cr = view.getUint8(56);
    const lf = view.getUint8(57);
    if (cr !== 0x0d || lf !== 0x0a) {
      throw new Error(`Bukan protokol Trojan: expected CRLF at bytes 56-57, got 0x${cr.toString(16)} 0x${lf.toString(16)}`);
    }
    
    // Parse port (bytes 59-60)
    const port = view.getUint16(59);
    if (port === 0 || port > 65535) {
      throw new Error(`Port tidak valid: ${port}`);
    }
    
    // Parse address type (byte 61)
    const addressType = view.getUint8(61);
    let address, nextIndex;
    
    if (addressType === 1) { // IPv4
      if (buffer.byteLength < 62 + 4) {
        throw new Error(`IPv4 address terpotong: need 4 bytes, have ${buffer.byteLength - 62}`);
      }
      address = Array.from(new Uint8Array(buffer, 62, 4)).join('.');
      nextIndex = 62 + 4;
      Logger.debug('TROJAN_PARSE_IPV4', { address, nextIndex });
      
    } else if (addressType === 3) { // Domain name
      const domainLen = view.getUint8(62);
      if (buffer.byteLength < 63 + domainLen) {
        throw new Error(`Domain name terpotong: need ${domainLen} bytes, have ${buffer.byteLength - 63}`);
      }
      address = new TextDecoder().decode(new Uint8Array(buffer, 63, domainLen));
      nextIndex = 63 + domainLen;
      Logger.debug('TROJAN_PARSE_DOMAIN', { address, domainLen, nextIndex });
      
    } else if (addressType === 2) { // IPv6
      if (buffer.byteLength < 62 + 16) {
        throw new Error(`IPv6 address terpotong: need 16 bytes, have ${buffer.byteLength - 62}`);
      }
      const parts = [];
      for (let i = 0; i < 8; i++) {
        parts.push(view.getUint16(62 + i * 2).toString(16));
      }
      address = parts.join(':');
      nextIndex = 62 + 16;
      Logger.debug('TROJAN_PARSE_IPV6', { address, nextIndex });
      
    } else {
      throw new Error(`Tipe alamat tidak didukung: ${addressType} (1=IPv4, 2=IPv6, 3=Domain)`);
    }
    
    // Find CRLF after address
    let rawDataIndex = nextIndex;
    if (rawDataIndex + 2 <= buffer.byteLength) {
      const cr2 = view.getUint8(rawDataIndex);
      const lf2 = view.getUint8(rawDataIndex + 1);
      if (cr2 === 0x0d && lf2 === 0x0a) {
        rawDataIndex += 2;
        Logger.debug('TROJAN_CRLF_AFTER_ADDR_FOUND', { rawDataIndex });
      }
    }
    
    return { address, port, rawDataIndex };
    
  } catch (error) {
    Logger.error('TROJAN_PARSE_ERROR', error, { bufferSize: buffer?.byteLength });
    throw error;
  }
}

// ==================== UTILITY FUNCTIONS ====================
function cleanup(state) {
  const { requestId } = state;
  
  Logger.debug('CLEANUP_START', { requestId, connected: state.connected });
  
  try {
    if (state.writer) {
      state.writer.releaseLock();
      Logger.debug('CLEANUP_WRITER_RELEASED', { requestId });
    }
  } catch (error) {
    Logger.error('CLEANUP_WRITER_ERROR', error, { requestId });
  }
  
  try {
    if (state.tcpSocket) {
      state.tcpSocket.close();
      Logger.debug('CLEANUP_SOCKET_CLOSED', { requestId });
    }
  } catch (error) {
    Logger.error('CLEANUP_SOCKET_ERROR', error, { requestId });
  }
  
  try {
    if (state.keepAliveTimer) {
      clearInterval(state.keepAliveTimer);
      Logger.debug('CLEANUP_TIMER_CLEARED', { requestId });
    }
  } catch (error) {
    Logger.error('CLEANUP_TIMER_ERROR', error, { requestId });
  }
  
  state.writer = null;
  state.tcpSocket = null;
  state.connected = false;
  
  Logger.debug('CLEANUP_COMPLETE', { requestId });
}

function safeClose(ws) {
  try {
    if (ws && ws.readyState === 1) { // OPEN
      ws.close(1000, 'done');
      Logger.debug('WEBSOCKET_CLOSED', { readyState: ws.readyState });
    }
  } catch (error) {
    Logger.error('WEBSOCKET_CLOSE_ERROR', error);
  }
}