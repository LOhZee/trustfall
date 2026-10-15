const fs = require('node:fs');
const path = require('node:path');

function stageAssets(appDir, sourceDir = __dirname, dependencyDir = appDir) {
  if (!appDir) throw new Error('Usage: node stage-assets.js APP_DIR');
  const publicDir = path.join(appDir, 'public');
  const files = [
    [sourceDir, 'index.html', 'public/index.html'],
    [sourceDir, 'terminal.css', 'public/terminal.css'],
    [sourceDir, 'terminal_server.js', 'terminal_server.js'],
    [sourceDir, 'static-server.js', 'static-server.js']
  ];
  for (const [name, directory, stylesheet] of [
    ['@xterm/xterm', 'xterm', 'css/xterm.css'],
    ['@xterm/addon-fit', 'addon-fit']
  ]) {
    const entrypoint = require.resolve(name, { paths: [dependencyDir] });
    const packageDir = path.dirname(path.dirname(entrypoint));
    const bundle = path.basename(entrypoint);
    files.push(
      [packageDir, `lib/${bundle}`, `public/vendor/${directory}/${bundle}`],
      [packageDir, `lib/${bundle}.map`, `public/vendor/${directory}/${bundle}.map`],
      [packageDir, 'LICENSE', `public/vendor/${directory}/LICENSE`]
    );
    if (stylesheet) files.push([packageDir, stylesheet, `public/vendor/${directory}/xterm.css`]);
  }

  // Validate the complete allowlist before replacing the public tree.
  for (const [root, relative] of files) {
    const source = path.join(root, relative);
    const resolved = path.relative(fs.realpathSync(root), fs.realpathSync(source));
    if (resolved === '..' || resolved.startsWith(`..${path.sep}`) || path.isAbsolute(resolved) ||
        !fs.statSync(source).isFile()) {
      throw new Error(`Required asset is not a regular file inside its source directory: ${relative}`);
    }
  }
  fs.rmSync(publicDir, { recursive: true, force: true });
  for (const [root, relative, destination] of files) {
    const target = path.join(appDir, destination);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(root, relative), target);
  }
}

if (require.main === module) {
  try {
    stageAssets(process.argv[2]);
  } catch (error) {
    console.error(`Asset staging failed: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { stageAssets };
