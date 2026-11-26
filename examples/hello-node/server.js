// A minimal web app for trying out Nook: "/" greets (with the visitor's
// email when the gateway signed them in), "/healthz" says ok, and "/ws" is
// a WebSocket echo (RFC 6455, no dependencies) for testing the gateway.
"use strict";

const http = require("node:http");
const crypto = require("node:crypto");

const port = Number(process.env.PORT || 8080);
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_FRAME = 64 * 1024;

const server = http.createServer((req, res) => {
  console.log(`${req.method} ${req.url}`);
  if (req.method === "GET" && req.url === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok\n");
    return;
  }
  if (req.method === "GET" && req.url === "/") {
    const who = req.headers["x-nook-email"];
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`Hello from a Nook app written for Node.js${who ? `, ${who}` : ""}!\n`);
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found\n");
});

// WebSocket echo on /ws: text and binary messages come back unchanged.
server.on("upgrade", (req, socket) => {
  const key = req.headers["sec-websocket-key"];
  if (req.url !== "/ws" || !key || (req.headers.upgrade || "").toLowerCase() !== "websocket") {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    return;
  }
  const accept = crypto.createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  console.log("websocket opened");
  let buffer = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    for (;;) {
      const frame = parseFrame(buffer);
      if (!frame) return;
      buffer = buffer.subarray(frame.length);
      if (frame.opcode === 0x8) {
        socket.end(encodeFrame(0x8, Buffer.alloc(0)));
        return;
      }
      if (frame.opcode === 0x9) {
        socket.write(encodeFrame(0xa, frame.payload));
      } else if (frame.opcode === 0x1 || frame.opcode === 0x2) {
        socket.write(encodeFrame(frame.opcode, frame.payload));
      }
    }
  });
  socket.on("error", () => socket.destroy());
  socket.on("close", () => console.log("websocket closed"));
});

// parseFrame decodes one masked client frame, or returns null when more
// bytes are needed. Oversized or unmasked frames close the connection.
function parseFrame(buf) {
  if (buf.length < 2) return null;
  const opcode = buf[0] & 0x0f;
  const masked = (buf[1] & 0x80) !== 0;
  let len = buf[1] & 0x7f;
  let offset = 2;
  if (len === 126) {
    if (buf.length < 4) return null;
    len = buf.readUInt16BE(2);
    offset = 4;
  } else if (len === 127) {
    if (buf.length < 10) return null;
    len = Number(buf.readBigUInt64BE(2));
    offset = 10;
  }
  if (len > MAX_FRAME || !masked) return { opcode: 0x8, payload: Buffer.alloc(0), length: buf.length };
  if (buf.length < offset + 4 + len) return null;
  const mask = buf.subarray(offset, offset + 4);
  const payload = Buffer.from(buf.subarray(offset + 4, offset + 4 + len));
  for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
  return { opcode, payload, length: offset + 4 + len };
}

// encodeFrame builds an unmasked server frame (payloads below 64 KiB).
function encodeFrame(opcode, payload) {
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x80 | opcode, payload.length]);
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  }
  return Buffer.concat([header, payload]);
}

server.listen(port, () => console.log(`listening on :${port}`));

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
