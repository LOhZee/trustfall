'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { runInNewContext } = require('node:vm');

function client({ authenticated = true } = {}) {
  const button = { disabled: false };
  const elements = {
    connect: { querySelector: () => button, addEventListener: (event, handler) => { submit = handler; } },
    secret: { value: 'disposable-client-fixture' },
    status: { className: '', textContent: '' },
    terminal: {}
  };
  let submit;
  let options;
  let socket;
  let fits = 0;
  const disposed = [];
  const context = {
    document: { getElementById: (id) => elements[id] },
    location: { protocol: 'https:', host: 'diagnostic.example' },
    window: { addEventListener() {} },
    fetch: async () => ({ ok: authenticated }),
    Terminal: class {
      constructor(value) { options = value; }
      loadAddon() {}
      open() {}
      focus() {}
      onData() { return { dispose: () => disposed.push('input') }; }
      onResize() { return { dispose: () => disposed.push('resize') }; }
    },
    FitAddon: { FitAddon: class { fit() { fits++; } } },
    ResizeObserver: class {
      observe() {}
      disconnect() { disposed.push('observer'); }
    },
    WebSocket: class {
      static OPEN = 1;
      constructor() { socket = this; }
      send() {}
    }
  };
  runInNewContext(readFileSync(join(__dirname, 'public/terminal.js'), 'utf8'), context);
  return {
    elements, button, options, disposed,
    socket: () => socket, fits: () => fits,
    submit: () => submit({ preventDefault() {} })
  };
}

test('custom xterm colors and typography match the branded stylesheet', () => {
  const f = client();
  const css = readFileSync(join(__dirname, 'public/terminal.css'), 'utf8');
  assert.equal(f.options.theme.background, '#0a0a0f');
  assert.equal(f.options.theme.foreground, '#e2e8f0');
  assert.equal(f.options.theme.cursor, '#00d4ff');
  assert.equal(f.options.fontFamily, 'Menlo, Consolas, monospace');
  assert.equal(f.options.fontSize, 14);
  assert.ok(css.includes(`--bg: ${f.options.theme.background}`));
  assert.ok(css.includes(`--accent: ${f.options.theme.cursor}`));
  assert.match(css, /#connect\[hidden\]\s*\{\s*display:\s*none/);
  for (const state of ['connected', 'disconnected']) assert.ok(css.includes(`#status.${state}`));
  assert.match(css, /@media \(max-width: 600px\)/);
  assert.match(css, /@media \(max-height: 500px\)/);
});

test('successful connection applies the status badge and refits after hiding authentication', async () => {
  const f = client();
  await f.submit();
  assert.equal(f.elements.secret.value, '');
  assert.equal(f.elements.status.textContent, 'Connecting…');
  assert.equal(f.button.disabled, true);
  f.socket().onopen();
  assert.equal(f.elements.connect.hidden, true);
  assert.equal(f.elements.status.className, 'connected');
  assert.equal(f.elements.status.textContent, 'Connected');
  assert.equal(f.fits(), 2);
  f.socket().onclose();
  assert.equal(f.elements.status.className, 'disconnected');
  assert.match(f.elements.status.textContent, /Terminal closed/);
  assert.deepEqual(f.disposed, ['input', 'resize', 'observer']);
});

test('failed authentication shows disconnected styling without opening a WebSocket', async () => {
  const f = client({ authenticated: false });
  await f.submit();
  assert.equal(f.elements.status.className, 'disconnected');
  assert.match(f.elements.status.textContent, /Authentication failed/);
  assert.equal(f.elements.secret.value, '');
  assert.equal(f.button.disabled, false);
  assert.equal(f.socket(), undefined);
});

test('WebSocket errors show disconnected styling', async () => {
  const f = client();
  await f.submit();
  f.socket().onerror();
  assert.equal(f.elements.status.className, 'disconnected');
  assert.equal(f.elements.status.textContent, 'Terminal connection failed.');
});
