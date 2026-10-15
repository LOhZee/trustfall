const fs = require('node:fs/promises');
const path = require('node:path');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.map': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.txt': 'text/plain; charset=utf-8'
};

function isWithin(root, file) {
  const relative = path.relative(root, file);
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function createStaticHandler(publicDir) {
  const root = path.resolve(publicDir);
  return async (req, res) => {
    const reply = (status, message, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...headers });
      res.end(req.method === 'HEAD' ? undefined : message);
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      reply(405, 'Method not allowed', { Allow: 'GET, HEAD' });
      return;
    }

    let pathname;
    try {
      if (!req.url.startsWith('/') || req.url.startsWith('//') || req.url.includes('\\')) {
        throw new Error('Invalid request target');
      }
      // Reject decoded dot segments before URL normalization can erase them.
      const rawPathname = decodeURIComponent(req.url.split(/[?#]/, 1)[0]);
      if (/[\x00-\x1f\x7f\\]/.test(rawPathname)) throw new Error('Invalid pathname');
      if (rawPathname.split('/').some((part) => part.startsWith('.'))) {
        reply(404, 'Not found');
        return;
      }
      pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    } catch {
      reply(400, 'Bad request');
      return;
    }
    const file = path.resolve(root, `.${pathname === '/' ? '/index.html' : pathname}`);
    if (!isWithin(root, file)) {
      reply(404, 'Not found');
      return;
    }
    try {
      const realRoot = await fs.realpath(root);
      const realFile = await fs.realpath(file);
      if (!isWithin(realRoot, realFile) || !(await fs.stat(realFile)).isFile()) {
        reply(404, 'Not found');
        return;
      }
      const data = await fs.readFile(realFile);
      res.writeHead(200, {
        'Content-Type': MIME_TYPES[path.extname(realFile).toLowerCase()] || 'application/octet-stream',
        'Content-Length': data.length,
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(req.method === 'HEAD' ? undefined : data);
    } catch (error) {
      const missing = ['ENOENT', 'ENOTDIR', 'EACCES', 'ELOOP'].includes(error.code);
      reply(missing ? 404 : 500, missing ? 'Not found' : 'Internal server error');
    }
  };
}

module.exports = { createStaticHandler };
