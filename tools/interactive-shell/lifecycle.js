'use strict';

const { spawn } = require('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { createTerminalServer, validateSecret } = require('./server');

async function run({
  env = process.env, spawnTunnel = spawn, createServer = createTerminalServer,
  signals = process, log = console.log, discoveryMs = 60_000, durationMs = 115 * 60_000
} = {}) {
  const secret = env.INTERACTIVE_SHELL_ACCESS_SECRET;
  delete env.INTERACTIVE_SHELL_ACCESS_SECRET;
  validateSecret(secret);
  if (!env.INTERACTIVE_SHELL_SSH_KNOWN_HOSTS?.trim()) {
    throw new Error('Provision verified INTERACTIVE_SHELL_SSH_KNOWN_HOSTS before opening a tunnel.');
  }
  const directory = mkdtempSync(join(tmpdir(), 'interactive-shell-tunnel-'));
  const knownHosts = join(directory, 'known_hosts');
  const port = 8080;
  let tunnel;
  let terminal;
  let stopping = false;
  let endpointTimer;
  let durationTimer;
  let killTimer;
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });
  const onSignal = () => finish(130);
  function finish(code) {
    if (stopping) return;
    stopping = true;
    clearTimeout(endpointTimer);
    clearTimeout(durationTimer);
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) signals.off(signal, onSignal);
    try { terminal?.close(); }
    catch { log('Diagnostic server cleanup failed.'); code = 1; }
    if (tunnel && tunnel.exitCode === null && tunnel.signalCode === null) {
      tunnel.kill('SIGTERM');
      killTimer = setTimeout(() => tunnel.kill('SIGKILL'), 1000);
    }
    try { rmSync(directory, { recursive: true, force: true }); }
    catch { log('Temporary SSH directory cleanup failed.'); code = 1; }
    resolveDone(code);
  }
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) signals.on(signal, onSignal);
  durationTimer = setTimeout(() => {
    log('Diagnostic shell reached its 115-minute runtime limit.');
    finish(0);
  }, durationMs);
  try {
    writeFileSync(knownHosts, env.INTERACTIVE_SHELL_SSH_KNOWN_HOSTS + '\n', { mode: 0o600 });
    tunnel = spawnTunnel('ssh', [
      '-F', '/dev/null', '-T',
      '-o', 'BatchMode=yes', '-o', 'IdentityAgent=none', '-o', 'IdentityFile=none',
      '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${knownHosts}`,
      '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ExitOnForwardFailure=yes',
      '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
      '-R', `80:127.0.0.1:${port}`, 'nokey@localhost.run'
    ], {
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: directory, LANG: 'C.UTF-8' },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    tunnel.once('error', () => { log('SSH tunnel could not start.'); finish(1); });
    tunnel.once('exit', () => {
      clearTimeout(killTimer);
      if (!stopping) { log('SSH tunnel exited unexpectedly.'); finish(1); }
    });
    const origin = await new Promise((resolve) => {
      let output = '';
      const inspect = (chunk) => {
        output = (output + chunk.toString()).slice(-65_536);
        const match = output.match(/https:\/\/[a-z0-9-]+\.lhr\.life(?=[\s\x1b]|$)/);
        if (match) resolve(match[0]);
      };
      tunnel.stdout.on('data', inspect);
      tunnel.stderr.on('data', inspect);
      endpointTimer = setTimeout(() => {
        log('SSH tunnel did not publish an HTTPS endpoint within 60 seconds.');
        finish(1);
      }, discoveryMs);
      done.then(() => resolve(undefined));
    });
    clearTimeout(endpointTimer);
    if (!stopping) {
      terminal = createServer({
        secret, origin, cwd: env.GITHUB_WORKSPACE || process.cwd(),
        azureIdentifiers: {
          AZURE_CLIENT_ID: env.AZURE_CLIENT_ID,
          AZURE_TENANT_ID: env.AZURE_TENANT_ID
        },
        onSessionEnd: (code = 0) => finish(code)
      });
      terminal.server.on('error', () => { log('Diagnostic server failed.'); finish(1); });
      terminal.server.listen(port, '127.0.0.1', () => {
        log('Authenticated interactive diagnostic shell endpoint (secret required):');
        log(origin);
      });
    }
  } catch {
    log('Diagnostic shell startup failed.');
    finish(1);
  }
  return done;
}

if (require.main === module) {
  run().then((code) => { process.exitCode = code; }).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { run };
