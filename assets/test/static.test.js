const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { test, before, after } = require('node:test');
const { createStaticHandler } = require('../static-server');
const { stageAssets } = require('../stage-assets');

const assets = path.resolve(__dirname, '..');
let temporary;
let app;
let server;

before(async () => {
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'static-assets-'));
  app = path.join(temporary, 'app');
  stageAssets(app, assets, assets);
  server = http.createServer(createStaticHandler(path.join(app, 'public')));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (temporary) fs.rmSync(temporary, { recursive: true, force: true });
});

function request(target, method = 'GET') {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: server.address().port, path: target, method
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks)
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('staging publishes only the explicit browser allowlist, with backend beside public', () => {
  function list(directory, prefix = '') {
    return fs.readdirSync(directory).flatMap((name) => {
      const relative = path.join(prefix, name);
      return fs.statSync(path.join(directory, name)).isDirectory()
        ? list(path.join(directory, name), relative) : [relative];
    }).sort();
  }
  assert.deepEqual(list(path.join(app, 'public')), [
    'index.html', 'terminal.css',
    'vendor/addon-fit/LICENSE', 'vendor/addon-fit/addon-fit.js', 'vendor/addon-fit/addon-fit.js.map',
    'vendor/xterm/LICENSE', 'vendor/xterm/xterm.css', 'vendor/xterm/xterm.js', 'vendor/xterm/xterm.js.map'
  ]);
  for (const backend of ['terminal_server.js', 'static-server.js']) {
    assert.equal(fs.readFileSync(path.join(app, backend), 'utf8'),
      fs.readFileSync(path.join(assets, backend), 'utf8'));
  }
  assert.equal(fs.readFileSync(path.join(app, 'public/terminal.css'), 'utf8'),
    fs.readFileSync(path.join(assets, 'terminal.css'), 'utf8'));
});

test('staging removes stale public files and fails when required assets are absent', () => {
  const destination = path.join(temporary, 'restaged');
  stageAssets(destination, assets, assets);
  fs.writeFileSync(path.join(destination, 'public/backend.js'), 'not public');
  stageAssets(destination, assets, assets);
  assert.equal(fs.existsSync(path.join(destination, 'public/backend.js')), false);
  const incomplete = path.join(temporary, 'incomplete');
  fs.mkdirSync(incomplete);
  fs.copyFileSync(path.join(assets, 'index.html'), path.join(incomplete, 'index.html'));
  assert.throws(() => stageAssets(destination, incomplete, assets), /terminal\.css/);
  assert.equal(fs.existsSync(path.join(destination, 'public/index.html')), true);
});

test('HTML and CSS use only local runtime asset references that resolve successfully', async () => {
  const html = (await request('/')).body.toString();
  const references = [...html.matchAll(/(?:src|href)=["']([^"']+)["']/g)].map((match) => match[1]);
  assert.equal(references.length, 4);
  for (const reference of references) {
    assert.match(reference, /^\.\/(?!\/)/);
    const response = await request(`/${reference.slice(2)}`);
    assert.equal(response.status, 200, reference);
  }
  for (const stylesheet of ['/terminal.css', '/vendor/xterm/xterm.css']) {
    const css = (await request(stylesheet)).body.toString().replace(/\/\*[\s\S]*?\*\//g, '');
    assert.doesNotMatch(css, /@import|url\(\s*["']?(?:https?:)?\/\//i);
  }
  assert.doesNotMatch(html, /https?:\/\/|unpkg|eval\s*\(|import\s*\(/i);
});

test('root, query strings, encoded filenames and nested assets have correct content types', async () => {
  for (const [target, type] of [
    ['/', 'text/html'], ['/?version=1', 'text/html'],
    ['/terminal.css?v=1', 'text/css'], ['/terminal%2ecss', 'text/css'],
    ['/vendor/xterm/xterm.js?v=1', 'application/javascript'],
    ['/vendor/addon-fit/addon-fit.js', 'application/javascript'],
    ['/vendor/xterm/xterm.css', 'text/css'],
    ['/vendor/xterm/xterm.js.map', 'application/json']
  ]) {
    const response = await request(target);
    assert.equal(response.status, 200, target);
    assert.ok(response.headers['content-type'].startsWith(type), target);
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.equal(Number(response.headers['content-length']), response.body.length);
  }
});

test('nested images, fonts, JSON and unknown files are served without HTML fallbacks', async () => {
  const directory = path.join(app, 'public/nested');
  fs.mkdirSync(directory);
  for (const [extension, type] of Object.entries({
    svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
    gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', ico: 'image/x-icon',
    woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', otf: 'font/otf',
    json: 'application/json', mjs: 'application/javascript; charset=utf-8',
    bin: 'application/octet-stream'
  })) {
    fs.writeFileSync(path.join(directory, `asset.${extension}`), 'fixture');
    const response = await request(`/nested/asset.${extension}?test=1`);
    assert.equal(response.status, 200);
    assert.equal(response.headers['content-type'], type);
    assert.equal(response.body.toString(), 'fixture');
  }
});

test('HEAD returns GET headers without a body, including error responses', async () => {
  const get = await request('/terminal.css');
  const head = await request('/terminal.css', 'HEAD');
  assert.equal(head.status, 200);
  assert.equal(head.headers['content-type'], get.headers['content-type']);
  assert.equal(head.headers['content-length'], get.headers['content-length']);
  assert.equal(head.body.length, 0);
  for (const target of ['/missing', '/%zz']) {
    const response = await request(target, 'HEAD');
    assert.equal(response.status, target === '/missing' ? 404 : 400);
    assert.equal(response.body.length, 0);
  }
});

test('non-read methods are rejected', async () => {
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']) {
    const response = await request('/terminal.css', method);
    assert.equal(response.status, 405);
    assert.equal(response.headers.allow, 'GET, HEAD');
  }
});

test('missing files, directories, backend, package metadata and dotfiles are not public', async () => {
  fs.writeFileSync(path.join(app, 'public/.hidden'), 'private');
  for (const target of [
    '/missing.js', '/vendor', '/vendor/', '/terminal_server.js', '/static-server.js',
    '/stage-assets.js', '/package.json', '/package-lock.json', '/test/static.test.js',
    '/.hidden', '/%2ehidden', '/.git/config'
  ]) {
    const response = await request(target);
    assert.equal(response.status, 404, target);
    assert.equal(response.body.toString(), 'Not found');
  }
});

test('traversals, prefix-sibling escapes and file/directory symlink escapes are denied', async () => {
  const sibling = path.join(app, 'public-private');
  fs.mkdirSync(sibling);
  fs.writeFileSync(path.join(sibling, 'secret.txt'), 'private');
  fs.symlinkSync(path.join(sibling, 'secret.txt'), path.join(app, 'public/escape.txt'));
  fs.symlinkSync(sibling, path.join(app, 'public/escape-directory'));
  for (const target of [
    '/../terminal_server.js', '/./terminal_server.js', '/%2e%2e/terminal_server.js',
    '/%252e%252e/terminal_server.js',
    '/..%2fterminal_server.js', '/vendor/%2e%2e/%2e%2e/terminal_server.js',
    '/../public-private/secret.txt', '/escape.txt', '/escape-directory/secret.txt'
  ]) {
    const response = await request(target);
    assert.equal(response.status, 404, target);
    assert.equal(response.body.toString(), 'Not found');
  }
});

test('malformed encodings, nulls and backslash paths are rejected without leaking paths', async () => {
  for (const target of ['/%', '/%zz', '/%C0%AF', '/%00', '/%5c..%5csecret', '/\\secret', '//example.com/file']) {
    const response = await request(target);
    assert.equal(response.status, 400, target);
    assert.equal(response.body.toString(), 'Bad request');
  }
});
