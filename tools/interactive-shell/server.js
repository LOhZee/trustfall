'use strict';

const http = require('node:http');
const { readFileSync, readdirSync, mkdtempSync, rmSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');
const { WebSocketServer, WebSocket } = require('ws');
const pty = require('node-pty');

function validateSecret(secret) {
  if (typeof secret !== 'string' || !/^[\x21-\x7e]{32,256}$/.test(secret)) {
    throw new Error('Provision INTERACTIVE_SHELL_ACCESS_SECRET (32–256 printable non-space characters).');
  }
}

function killTerminal(shell) {
  if (Number.isInteger(shell.pid) && shell.pid > 1) {
    // Linux PTYs lead a session; job control can put children in other process groups.
    // Include every member of that session, not just the shell's process group.
    try {
      for (const pid of readdirSync('/proc').filter((name) => /^\d+$/.test(name))) {
        if (Number(pid) === shell.pid) continue;
        try {
          const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
          const session = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[3]);
          if (session === shell.pid) process.kill(Number(pid), 'SIGKILL');
        } catch {}
      }
    } catch {}
    try { process.kill(-shell.pid, 'SIGKILL'); } catch {}
  }
  try { shell.kill('SIGKILL'); } catch {}
}

function createTerminalServer({ secret, origin, cwd, spawn = pty.spawn, onSessionEnd = () => {} }) {
  validateSecret(secret);
  const url = new URL(origin);
  if (url.origin !== origin || !(url.protocol === 'https:' ||
      (url.protocol === 'http:' && url.hostname === '127.0.0.1'))) {
    throw new Error('An exact HTTPS origin (or local HTTP loopback origin) is required.');
  }
  const secure = url.protocol === 'https:';
  const digest = (value) => createHash('sha256').update(value).digest();
  const expected = digest(secret);
  secret = undefined;
  const assets = new Map([
    ['/', ['public/index.html', 'text/html; charset=utf-8']],
    ['/terminal.css', ['public/terminal.css', 'text/css; charset=utf-8']],
    ['/terminal.js', ['public/terminal.js', 'text/javascript; charset=utf-8']],
    ['/xterm.css', ['node_modules/@xterm/xterm/css/xterm.css', 'text/css; charset=utf-8']],
    ['/xterm.js', ['node_modules/@xterm/xterm/lib/xterm.js', 'text/javascript; charset=utf-8']],
    ['/addon-fit.js', ['node_modules/@xterm/addon-fit/lib/addon-fit.js', 'text/javascript; charset=utf-8']]
  ].map(([route, [file, type]]) => [route, { body: readFileSync(join(__dirname, file)), type }]));
  const sessions = new Map();
  let active;
  let closed = false;

  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    req.resume();
    if (req.url === '/session' && req.method === 'POST') {
      const bearer = req.headers.authorization;
      if (closed || req.headers.origin !== origin || typeof bearer !== 'string' ||
          !bearer.startsWith('Bearer ') || !timingSafeEqual(digest(bearer.slice(7)), expected)) {
        res.writeHead(401).end('Authentication required');
        return;
      }
      for (const [id, expires] of sessions) if (expires <= Date.now()) sessions.delete(id);
      if (active || sessions.size >= 8) {
        res.writeHead(409).end('Shell unavailable');
        return;
      }
      const id = randomBytes(32).toString('hex');
      sessions.set(id, Date.now() + 5 * 60_000);
      res.setHeader('Set-Cookie', `shell_session=${id}; HttpOnly; SameSite=Strict; Path=/terminal; Max-Age=300${secure ? '; Secure' : ''}`);
      res.writeHead(204).end();
      return;
    }
    if (req.method !== 'GET') {
      res.writeHead(405).end();
      return;
    }
    const asset = assets.get(req.url);
    if (!asset) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'Content-Type': asset.type }).end(asset.body);
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  const wss = new WebSocketServer({ noServer: true, maxPayload: 16_384, perMessageDeflate: false });
  server.on('upgrade', (req, socket, head) => {
    const cookie = /(?:^|; *)shell_session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '');
    const expires = cookie && sessions.get(cookie[1]);
    if (closed || active || req.url !== '/terminal' || req.headers.origin !== origin ||
        !expires || expires <= Date.now()) {
      socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
      return;
    }
    sessions.delete(cookie[1]);
    socket.on('error', () => {});
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws));
  });
  wss.on('connection', (ws) => {
    let home;
    let shell;
    let ended = false;
    let heartbeat;
    let dataSubscription;
    let exitSubscription;
    const finish = (exitCode = 0) => {
      if (ended) return;
      ended = true;
      clearInterval(heartbeat);
      dataSubscription?.dispose();
      exitSubscription?.dispose();
      if (shell) killTerminal(shell);
      ws.terminate();
      try {
        if (home) rmSync(home, { recursive: true, force: true });
      } catch {
        exitCode = 1;
      }
      active = undefined;
      onSessionEnd(exitCode);
    };
    active = { finish };
    ws.on('error', () => finish(1));
    ws.on('close', () => finish());
    try {
      home = mkdtempSync(join(tmpdir(), 'interactive-shell-home-'));
      shell = spawn('/bin/bash', ['--noprofile', '--norc'], {
        name: 'xterm-256color', cols: 80, rows: 24, cwd,
        env: { HOME: home, PATH: '/usr/local/bin:/usr/bin:/bin', TERM: 'xterm-256color', LANG: 'C.UTF-8' }
      });
      dataSubscription = shell.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) {
          if (ws.bufferedAmount > 1_048_576) finish();
          else ws.send(data);
        }
      });
      exitSubscription = shell.onExit(({ exitCode }) => finish(exitCode));
      ws.on('message', (data, binary) => {
        if (ended) return;
        try {
          if (binary) throw new Error('Binary input is unsupported');
          const message = JSON.parse(data.toString());
          if (message?.type === 'input' && typeof message.data === 'string' &&
              message.data.length <= 8192) {
            shell.write(message.data);
          } else if (message?.type === 'resize' &&
              Number.isInteger(message.cols) && message.cols >= 2 && message.cols <= 500 &&
              Number.isInteger(message.rows) && message.rows >= 1 && message.rows <= 300) {
            shell.resize(message.cols, message.rows);
          } else throw new Error('Invalid terminal message');
        } catch {
          finish(1);
        }
      });
      let alive = true;
      ws.on('pong', () => { alive = true; });
      heartbeat = setInterval(() => {
        if (!alive) finish();
        else { alive = false; ws.ping(); }
      }, 15_000);
      heartbeat.unref();
    } catch {
      finish(1);
    }
  });

  function close() {
    if (closed) return;
    closed = true;
    sessions.clear();
    active?.finish();
    for (const ws of wss.clients) ws.terminate();
    wss.close();
    server.close();
    server.closeAllConnections();
  }
  return { server, close };
}

module.exports = { createTerminalServer, validateSecret };

if (require.main === module) {
  const secret = process.env.INTERACTIVE_SHELL_ACCESS_SECRET;
  delete process.env.INTERACTIVE_SHELL_ACCESS_SECRET;
  let terminal;
  let timeout;
  const stop = () => { clearTimeout(timeout); terminal?.close(); };
  try {
    terminal = createTerminalServer({
      secret, origin: 'http://127.0.0.1:8080',
      cwd: process.env.GITHUB_WORKSPACE || process.cwd(), onSessionEnd: stop
    });
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.once(signal, stop);
    terminal.server.on('error', () => { stop(); process.exitCode = 1; });
    timeout = setTimeout(stop, 30 * 60_000);
    terminal.server.listen(8080, '127.0.0.1', () => {
      console.log('Local diagnostic shell: http://127.0.0.1:8080 (secret required; 30-minute limit)');
    });
  } catch (error) {
    console.error(error.message);
    stop();
    process.exitCode = 1;
  }
}
