// A minimal web app for trying out Nook: "/" greets, "/healthz" says ok.
"use strict";

const http = require("node:http");

const port = Number(process.env.PORT || 8080);

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok\n");
    return;
  }
  if (req.method === "GET" && req.url === "/") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("Hello from a Nook app written for Node.js!\n");
    return;
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found\n");
});

server.listen(port, () => console.log(`listening on :${port}`));

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
