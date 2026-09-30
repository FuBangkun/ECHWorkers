const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CF_FALLBACK_IPS = ['ProxyIP.CMLiussss.net'];// cm维护

// mux 帧协议：1 条 WS 二进制消息 = 1 帧（与客户端 mux.go 对应）
// +--------+------------+--------+------------------+
// | type 1B| streamID 4B| len 2B | payload (≤32KB)  |
// +--------+------------+--------+------------------+
// 注意：本协议与旧版 CONNECT/CONNECTED 文本协议互不兼容，两端须同时升级。
const FRAME = { SYN: 1, OPENED: 2, DATA: 3, FIN: 4, RST: 5 };
const HDR_LEN = 7;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

import { connect } from 'cloudflare:sockets';

export default {
    async fetch(request, env, ctx) {
        try {
            const token = '';
            const upgradeHeader = request.headers.get('Upgrade');

            if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
                return new URL(request.url).pathname === '/'
                    ? new Response('WebSocket Mux Proxy Server', { status: 200 })
                    : new Response('Expected WebSocket', { status: 426 });
            }

            if (token && request.headers.get('Sec-WebSocket-Protocol') !== token) {
                return new Response('Unauthorized', { status: 401 });
            }

            const [client, server] = Object.values(new WebSocketPair());
            server.binaryType = 'arraybuffer';
            server.accept();

            try {
                handleMuxSession(server);
            } catch (e) {
                safeCloseWebSocket(server);
                throw e;
            }

            const responseInit = {
                status: 101,
                webSocket: client
            };

            if (token) {
                responseInit.headers = { 'Sec-WebSocket-Protocol': token };
            }

            return new Response(null, responseInit);

        } catch (err) {
            return new Response(err.toString(), { status: 500 });
        }
    },
};

function handleMuxSession(webSocket) {
    const streams = new Map(); // sid -> { socket, writer }
    let isClosed = false;

    const sendFrame = (type, sid, payload) => {
        if (isClosed) return;
        try {
            const plen = payload ? payload.length : 0;
            const buf = new Uint8Array(HDR_LEN + plen);
            const view = new DataView(buf.buffer);
            buf[0] = type;
            view.setUint32(1, sid);
            view.setUint16(5, plen);
            if (payload) buf.set(payload, HDR_LEN);
            webSocket.send(buf);
        } catch {}
    };

    const resetStream = (sid) => {
        const st = streams.get(sid);
        if (!st) return;
        streams.delete(sid);
        try { st.writer?.releaseLock(); } catch {}
        try { st.socket?.close(); } catch {}
    };

    const cleanup = () => {
        if (isClosed) return;
        isClosed = true;
        for (const sid of [...streams.keys()]) resetStream(sid);
        try { webSocket.close(1000, 'Server closed'); } catch {}
    };

    // 把出站 socket 的数据泵成 DATA 帧；结束时 FIN，异常时 RST。
    const pumpSocketToStream = async (sid, socket) => {
        const reader = socket.readable.getReader();
        try {
            while (!isClosed && streams.has(sid)) {
                const { done, value } = await reader.read();
                if (done) break;
                if (value?.byteLength > 0) sendFrame(FRAME.DATA, sid, value);
            }
            sendFrame(FRAME.FIN, sid);
        } catch {
            sendFrame(FRAME.RST, sid);
        } finally {
            try { reader.releaseLock(); } catch {}
        }
    };

    const connectRemote = async (sid, addr) => {
        const { host, port } = parseAddress(addr);
        const attempts = [null, ...CF_FALLBACK_IPS];

        for (let i = 0; i < attempts.length; i++) {
            let socket = null;
            try {
                socket = connect({ hostname: attempts[i] || host, port });
                if (socket.opened) await socket.opened;
                const writer = socket.writable.getWriter();
                streams.set(sid, { socket, writer });
                sendFrame(FRAME.OPENED, sid);
                await pumpSocketToStream(sid, socket);
                return;
            } catch (err) {
                try { socket?.close(); } catch {}
                if (!isCFError(err) || i === attempts.length - 1) {
                    sendFrame(FRAME.OPENED, sid,
                        encoder.encode('ERR:' + (err?.message || 'connect failed')));
                    return;
                }
            }
        }
    };

    webSocket.addEventListener('message', (event) => {
        if (isClosed) return;
        const data = event.data;
        if (!(data instanceof ArrayBuffer) || data.byteLength < HDR_LEN) return;

        const view = new DataView(data);
        const type = view.getUint8(0);
        const sid = view.getUint32(1);
        const len = view.getUint16(5);
        if (HDR_LEN + len > data.byteLength) return;
        const payload = new Uint8Array(data, HDR_LEN, len);

        switch (type) {
            case FRAME.SYN: {
                if (streams.has(sid)) return;
                connectRemote(sid, decoder.decode(payload))
                    .catch(() => sendFrame(FRAME.RST, sid));
                break;
            }
            case FRAME.DATA: {
                const st = streams.get(sid);
                if (st) {
                    st.writer.write(payload).catch(() => resetStream(sid));
                }
                break;
            }
            // 客户端为全关闭语义，FIN 与 RST 统一按中止处理
            case FRAME.FIN:
            case FRAME.RST: {
                resetStream(sid);
                break;
            }
        }
    });

    webSocket.addEventListener('close', cleanup);
    webSocket.addEventListener('error', cleanup);
}

function parseAddress(addr) {
    if (addr[0] === '[') {
        const end = addr.indexOf(']');
        return {
            host: addr.substring(1, end),
            port: parseInt(addr.substring(end + 2), 10)
        };
    }
    const sep = addr.lastIndexOf(':');
    return {
        host: addr.substring(0, sep),
        port: parseInt(addr.substring(sep + 1), 10)
    };
}

const isCFError = (err) => {
    const msg = err?.message?.toLowerCase() || '';
    return msg.includes('proxy request') ||
        msg.includes('cannot connect') ||
        msg.includes('cloudflare');
};

function safeCloseWebSocket(ws) {
    try {
        if (ws.readyState === WS_READY_STATE_OPEN ||
            ws.readyState === WS_READY_STATE_CLOSING) {
            ws.close(1000, 'Server closed');
        }
    } catch {}
}
