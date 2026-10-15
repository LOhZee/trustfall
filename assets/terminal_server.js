const fs = require('fs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const pty = require('node-pty');

const PORT = Number(process.env.PORT || 8080);
const PUBLIC_DIR = path.join(__dirname, 'public');
const shells = new Set();
let ending = false;

const server = http.createServer((req, res) => {
  let filePath = path.join(PUBLIC_DIR, req.url === '/' ? 'index.html' : req.url);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Access denied');
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath);
    const contentType = ext === '.css' ? 'text/css' : ext === '.js' ? 'application/javascript' : 'text/html';
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  const shell = pty.spawn('/bin/bash', [], {
    name: 'xterm-256color',
    cols: 80,
    rows: 24,
    cwd: process.env.GITHUB_WORKSPACE,
    env: process.env
  });
  shells.add(shell);
  let disconnected = false;

  shell.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  });

  shell.onExit(({ exitCode }) => {
    shells.delete(shell);
    if (disconnected || ending) return;
    ending = true;
    fs.writeFileSync('/tmp/terminal_exit_code', String(exitCode));
    for (const otherShell of shells) otherShell.kill();
    process.exit(exitCode);
  });

  ws.on('message', (message) => {
    const data = message.toString();
    try {
      const json = JSON.parse(data);
      if (json.type === 'resize') {
        shell.resize(json.cols, json.rows);
      } else {
        shell.write(data);
      }
    } catch {
      shell.write(data);
    }
  });

  ws.on('close', () => {
    disconnected = true;
    shell.kill();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Terminal server listening on port ${PORT}`);
});
