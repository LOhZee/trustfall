'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { randomBytes } = require('node:crypto');
const { existsSync } = require('node:fs');
const { run } = require('./lifecycle');

function harness(options = {}) {
  const tunnel = new EventEmitter();
  tunnel.stdout = new PassThrough();
  tunnel.stderr = new PassThrough();
  tunnel.exitCode = null;
  tunnel.signalCode = null;
  const kills = [];
  tunnel.kill = (signal) => {
    kills.push(signal);
    tunnel.signalCode = signal;
    process.nextTick(() => tunnel.emit('exit', null, signal));
  };
  const server = new EventEmitter();
  let started;
  let closes = 0;
  let spawnArgs;
  server.listen = (port, host, callback) => { started = { port, host }; callback(); };
  const signals = new EventEmitter();
  const logs = [];
  const env = {
    INTERACTIVE_SHELL_ACCESS_SECRET: randomBytes(32).toString('hex'),
    INTERACTIVE_SHELL_SSH_KNOWN_HOSTS: 'localhost.run ssh-ed25519 test-fixture-not-a-real-key',
    GITHUB_WORKSPACE: '/workspace', APPLICATION_SECRET: 'must-not-be-inherited'
  };
  let config;
  const done = run({
    env, signals, log: (line) => logs.push(line),
    discoveryMs: 100, durationMs: 1000,
    spawnTunnel: (...args) => { spawnArgs = args; return tunnel; },
    createServer: (value) => { config = value; return { server, close: () => { closes++; } }; },
    ...options
  });
  return {
    tunnel, server, signals, logs, kills, done, env,
    config: () => config, started: () => started, closes: () => closes, spawnArgs: () => spawnArgs
  };
}

test('tunnel endpoint discovery starts loopback server and session completion cleans up', async () => {
  const f = harness();
  f.tunnel.stderr.write('https://fixture.');
  f.tunnel.stderr.write('lhr.life\n');
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(f.started(), { port: 8080, host: '127.0.0.1' });
  assert.equal(f.config().origin, 'https://fixture.lhr.life');
  assert.equal(f.config().cwd, '/workspace');
  assert.equal(f.env.INTERACTIVE_SHELL_ACCESS_SECRET, undefined);
  const [command, args, spawnOptions] = f.spawnArgs();
  assert.equal(command, 'ssh');
  assert.ok(args.includes('StrictHostKeyChecking=yes'));
  assert.ok(args.includes('80:127.0.0.1:8080'));
  assert.deepEqual(Object.keys(spawnOptions.env).sort(), ['HOME', 'LANG', 'PATH']);
  assert.ok(!f.logs.some((line) => line.includes(f.config().secret)));
  f.config().onSessionEnd();
  assert.equal(await f.done, 0);
  assert.deepEqual(f.kills, ['SIGTERM']);
  assert.equal(f.closes(), 1);
  assert.ok(!existsSync(spawnOptions.env.HOME));
  assert.equal(f.signals.listenerCount('SIGTERM'), 0);
});

test('missing credentials or pinned SSH hosts never start a tunnel', async () => {
  for (const env of [{}, { INTERACTIVE_SHELL_ACCESS_SECRET: randomBytes(32).toString('hex') }]) {
    await assert.rejects(run({ env, spawnTunnel: () => assert.fail('Tunnel must not start') }));
  }
});

test('discovery timeout, tunnel errors, early exits, cancellation, and runtime bounds clean up', async (t) => {
  for (const mode of ['discovery timeout', 'error', 'exit', 'SIGINT', 'SIGTERM', 'SIGHUP', 'runtime']) {
    await t.test(mode, async () => {
      const f = harness({ discoveryMs: 30, durationMs: mode === 'runtime' ? 10 : 1000 });
      if (mode === 'error') f.tunnel.emit('error', new Error('SSH failure'));
      if (mode === 'exit') {
        f.tunnel.exitCode = 1;
        f.tunnel.emit('exit', 1);
      }
      if (mode.startsWith('SIG')) f.signals.emit(mode);
      const code = await f.done;
      assert.equal(code, mode.startsWith('SIG') ? 130 : mode === 'runtime' ? 0 : 1);
      assert.equal(f.started(), undefined);
      assert.ok(!existsSync(f.spawnArgs()[2].env.HOME));
    });
  }
});

test('server errors and established tunnel loss clean up both resources', async (t) => {
  for (const mode of ['server error', 'tunnel loss']) {
    await t.test(mode, async () => {
      const f = harness();
      f.tunnel.stdout.write('https://fixture.lhr.life\n');
      await new Promise((resolve) => setImmediate(resolve));
      if (mode === 'server error') f.server.emit('error', new Error('EADDRINUSE'));
      else { f.tunnel.exitCode = 1; f.tunnel.emit('exit', 1); }
      assert.equal(await f.done, 1);
      assert.equal(f.closes(), 1);
    });
  }
});
