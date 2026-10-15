'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const http = require('node:http');
const { randomBytes } = require('node:crypto');
const { existsSync, readFileSync } = require('node:fs');
const { WebSocket } = require('ws');
const { createTerminalServer } = require('./server');

const secret = randomBytes(32).toString('hex');
const origin = 'https://diagnostic.example';

async function fixture(t, options = {}) {
  const terminal = createTerminalServer({ secret, origin, cwd: __dirname, ...options });
  terminal.server.listen(0, '127.0.0.1');
  await once(terminal.server, 'listening');
  t.after(() => terminal.close());
  const base = `http://127.0.0.1:${terminal.server.address().port}`;
  const request = (path, { method = 'GET', headers = {} } = {}) => new Promise((resolve, reject) => {
    const req = http.request(base + path, { method, headers }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
  const login = (headers = {}) => request('/session', {
    method: 'POST', headers: { Origin: origin, Authorization: ['Bearer', secret].join(' '), ...headers }
  });
  const connect = (cookie, headers = {}, path = '/terminal') => new WebSocket(base.replace('http:', 'ws:') + path, {
    headers: { Origin: origin, ...(cookie ? { Cookie: cookie } : {}), ...headers }
  });
  return { ...terminal, request, login, connect };
}

async function denied(ws) {
  ws.on('error', () => {});
  const status = await new Promise((resolve, reject) => {
    ws.once('unexpected-response', (req, res) => { res.resume(); resolve(res.statusCode); });
    ws.once('open', () => reject(new Error('Unexpected authenticated connection')));
  });
  ws.terminate();
  assert.equal(status, 401);
}

function fakeShell() {
  let onExit;
  let options;
  const calls = { writes: [], resizes: [], kills: 0 };
  const shell = {
    pid: undefined,
    onData: () => ({ dispose() {} }),
    onExit: (callback) => { onExit = callback; return { dispose() {} }; },
    write: (data) => calls.writes.push(data),
    resize: (...size) => calls.resizes.push(size),
    kill: () => { calls.kills++; }
  };
  return {
    shell, calls, exit: () => onExit({ exitCode: 0 }),
    options: () => options,
    spawn: (file, args, config) => { options = config; return shell; }
  };
}

test('missing credentials fail closed before a server or PTY is created', () => {
  for (const value of [undefined, '', 'short', ' '.repeat(64)]) {
    assert.throws(() => createTerminalServer({ secret: value, origin }), /ACCESS_SECRET/);
  }
  assert.throws(() => createTerminalServer({ secret, origin: 'http://public.example' }), /HTTPS/);
});

test('only allowlisted assets are served with correct content types and no secrets', async (t) => {
  const f = await fixture(t, { spawn: () => assert.fail('Static requests cannot spawn a shell') });
  for (const [path, type] of [
    ['/', 'text/html'], ['/terminal.css', 'text/css'], ['/terminal.js', 'text/javascript'],
    ['/xterm.css', 'text/css'], ['/xterm.js', 'text/javascript'], ['/addon-fit.js', 'text/javascript']
  ]) {
    const response = await f.request(path);
    assert.equal(response.status, 200);
    assert.ok(response.headers['content-type'].startsWith(type));
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.ok(!response.body.includes(secret));
    if (path === '/') {
      for (const asset of ['/terminal.js', '/xterm.js', '/addon-fit.js', '/xterm.css', '/terminal.css']) {
        assert.ok(response.body.includes(asset));
      }
    }
  }
  for (const path of ['/server.js', '/package.json', '/.git/config', '/%2e%2e/server.js',
    '/node_modules/ws/index.js', '/terminal.js?secret=bad', '/unknown', '/../server.js']) {
    assert.equal((await f.request(path)).status, 404);
  }
  assert.equal((await f.request('/', { method: 'POST' })).status, 405);
});

test('unauthenticated, cross-origin, missing-origin, and query-token clients cannot spawn PTYs', async (t) => {
  let spawns = 0;
  const f = await fixture(t, { spawn: () => { spawns++; assert.fail('Unauthorized PTY'); } });
  for (const headers of [
    { Authorization: '' }, { Authorization: 'Basic invalid' }, { Origin: 'https://attacker.example' },
    { Origin: '' }
  ]) assert.equal((await f.login(headers)).status, 401);
  await denied(f.connect());
  await denied(f.connect(undefined, {}, '/terminal?token=' + secret));
  const auth = await f.login();
  assert.equal(auth.status, 204);
  assert.match(auth.headers['set-cookie'][0], /HttpOnly; SameSite=Strict/);
  assert.match(auth.headers['set-cookie'][0], /; Secure$/);
  const cookie = auth.headers['set-cookie'][0].split(';')[0];
  await denied(f.connect(cookie, { Origin: 'https://attacker.example' }));
  await denied(f.connect(cookie, { Origin: '' }));
  assert.equal(spawns, 0);
});

test('authenticated input and resize work; disconnect cleans PTY and consumes session', async (t) => {
  const fake = fakeShell();
  let ended = 0;
  const f = await fixture(t, { spawn: fake.spawn, onSessionEnd: () => ended++ });
  const cookie = (await f.login()).headers['set-cookie'][0].split(';')[0];
  const ws = f.connect(cookie);
  await once(ws, 'open');
  const home = fake.options().env.HOME;
  assert.equal(fake.options().cwd, __dirname);
  assert.deepEqual(Object.keys(fake.options().env).sort(), ['HOME', 'LANG', 'PATH', 'TERM']);
  assert.equal((await f.login()).status, 409);
  ws.send(JSON.stringify({ type: 'input', data: 'pwd\r' }));
  ws.send(JSON.stringify({ type: 'resize', cols: 100, rows: 40 }));
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.deepEqual(fake.calls.writes, ['pwd\r']);
  assert.deepEqual(fake.calls.resizes, [[100, 40]]);
  ws.close();
  await once(ws, 'close');
  assert.equal(fake.calls.kills, 1);
  assert.equal(ended, 1);
  assert.ok(!existsSync(home));
  await denied(f.connect(cookie));
});

test('expired sessions cannot upgrade or spawn a shell', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = await fixture(t, { spawn: () => assert.fail('Expired session cannot spawn a PTY') });
  const cookie = (await f.login()).headers['set-cookie'][0].split(';')[0];
  t.mock.timers.tick(5 * 60_000 + 1);
  await denied(f.connect(cookie));
});

test('invalid input and resize messages terminate rather than reach the shell', async (t) => {
  for (const value of [
    '{', 'echo raw command', 'null', '{"type":"input","data":42}', '{"type":"other"}',
    '{"type":"resize","cols":0,"rows":24}', '{"type":"resize","cols":80,"rows":99999}',
    '{"type":"resize","cols":80.5,"rows":24}', '{"type":"resize","cols":"80","rows":24}',
    JSON.stringify({ type: 'input', data: 'x'.repeat(8193) }), Buffer.from('binary'),
    'x'.repeat(20_000)
  ]) {
    await t.test(String(value).slice(0, 50), async (t) => {
      const fake = fakeShell();
      const f = await fixture(t, { spawn: fake.spawn });
      const ws = f.connect((await f.login()).headers['set-cookie'][0].split(';')[0]);
      await once(ws, 'open');
      ws.send(value);
      await once(ws, 'close');
      assert.deepEqual(fake.calls.writes, []);
      assert.deepEqual(fake.calls.resizes, []);
      assert.equal(fake.calls.kills, 1);
    });
  }
});

test('server shutdown, shell exit, and spawn errors close sockets and clean homes', async (t) => {
  for (const mode of ['shutdown', 'exit', 'spawn failure']) {
    await t.test(mode, async (t) => {
      const fake = fakeShell();
      const f = await fixture(t, {
        spawn: mode === 'spawn failure' ? () => { throw new Error('failed'); } : fake.spawn
      });
      const ws = f.connect((await f.login()).headers['set-cookie'][0].split(';')[0]);
      const closed = once(ws, 'close');
      await once(ws, 'open');
      if (mode === 'exit') fake.exit();
      if (mode === 'shutdown') f.close();
      await closed;
      if (mode !== 'spawn failure') {
        assert.equal(fake.calls.kills, 1);
        assert.ok(!existsSync(fake.options().env.HOME));
      }
      f.close();
    });
  }
});

test('real authenticated PTY supports output, resize, cwd, and an allowlisted environment', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t);
  const ws = f.connect((await f.login()).headers['set-cookie'][0].split(';')[0]);
  t.after(() => ws.terminate());
  let output = '';
  ws.on('message', (data) => { output += data.toString(); });
  await once(ws, 'open');
  ws.send(JSON.stringify({ type: 'resize', cols: 101, rows: 39 }));
  // Construct markers inside Bash so echoed input cannot satisfy output assertions.
  ws.send(JSON.stringify({ type: 'input', data: "printf 'REAL_%s\\n' PTY; pwd; stty size; printenv | cut -d= -f1 | sort; printf 'DONE_%s\\n' MARKER\r" }));
  for (let i = 0; i < 200 && !output.includes('DONE_MARKER'); i++) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.match(output, /REAL_PTY/);
  assert.ok(output.includes(__dirname));
  assert.match(output, /39 101/);
  assert.ok(!output.includes('INTERACTIVE_SHELL_ACCESS_SECRET'));
  assert.ok(!output.includes('ACTIONS_ID_TOKEN_REQUEST_TOKEN'));
  assert.match(output, /DONE_MARKER/);
  ws.send(JSON.stringify({ type: 'input', data: 'exit\r' }));
  await once(ws, 'close');
});

test('disconnect terminates a real shell and its running job', { timeout: 10_000 }, async (t) => {
  const f = await fixture(t);
  const ws = f.connect((await f.login()).headers['set-cookie'][0].split(';')[0]);
  t.after(() => ws.terminate());
  let output = '';
  ws.on('message', (data) => { output += data.toString(); });
  await once(ws, 'open');
  ws.send(JSON.stringify({
    type: 'input', data: 'sleep 120 & child=$!; printf "CHILD_PID:%s\\n" "$child"; wait "$child"\r'
  }));
  for (let i = 0; i < 200 && !/CHILD_PID:\d+/.test(output); i++) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const pid = Number(/CHILD_PID:(\d+)/.exec(output)?.[1]);
  assert.ok(pid > 1, 'Bash must report its child PID');
  t.after(() => { try { process.kill(pid, 'SIGKILL'); } catch {} });
  const running = () => {
    try { return !/^State:\s+Z/m.test(readFileSync(`/proc/${pid}/status`, 'utf8')); }
    catch { return false; }
  };
  assert.ok(running());
  ws.close();
  await once(ws, 'close');
  for (let i = 0; i < 100 && running(); i++) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(!running(), 'PTY child must terminate on disconnect');
});
