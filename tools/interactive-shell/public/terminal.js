'use strict';

const form = document.getElementById('connect');
const secret = document.getElementById('secret');
const status = document.getElementById('status');
const terminal = new Terminal({
  cursorBlink: true,
  cursorStyle: 'block',
  fontSize: 14,
  fontFamily: 'Menlo, Consolas, monospace',
  theme: {
    background: '#0a0a0f',
    foreground: '#e2e8f0',
    cursor: '#00d4ff',
    cursorAccent: '#0a0a0f',
    selectionBackground: '#35305b',
    black: '#12121a',
    red: '#ff8585',
    green: '#6ee7b7',
    yellow: '#ffdc80',
    blue: '#80bfff',
    magenta: '#d4a5ff',
    cyan: '#00d4ff',
    white: '#e2e8f0',
    brightBlack: '#94a3b8',
    brightRed: '#ffaaaa',
    brightGreen: '#a3ffa3',
    brightYellow: '#ffe9ad',
    brightBlue: '#b0d6ff',
    brightMagenta: '#e5c5ff',
    brightCyan: '#b0fff4',
    brightWhite: '#ffffff'
  }
});
const fit = new FitAddon.FitAddon();
terminal.loadAddon(fit);
terminal.open(document.getElementById('terminal'));
fit.fit();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = form.querySelector('button');
  button.disabled = true;
  status.className = '';
  status.textContent = 'Connecting…';
  try {
    const response = await fetch('/session', {
      method: 'POST',
      headers: { Authorization: ['Bearer', secret.value].join(' ') },
      credentials: 'same-origin',
      cache: 'no-store'
    });
    secret.value = '';
    if (!response.ok) throw new Error('Authentication failed or shell unavailable.');
    const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/terminal`);
    const send = (message) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
    };
    const input = terminal.onData((data) => send({ type: 'input', data }));
    const resize = terminal.onResize(({ cols, rows }) => send({ type: 'resize', cols, rows }));
    const observer = new ResizeObserver(() => fit.fit());
    observer.observe(document.getElementById('terminal'));
    socket.onopen = () => {
      form.hidden = true;
      status.className = 'connected';
      status.textContent = 'Connected';
      fit.fit();
      send({ type: 'resize', cols: terminal.cols, rows: terminal.rows });
      terminal.focus();
    };
    socket.onmessage = ({ data }) => terminal.write(data);
    socket.onerror = () => {
      status.className = 'disconnected';
      status.textContent = 'Terminal connection failed.';
    };
    socket.onclose = () => {
      status.className = 'disconnected';
      status.textContent = 'Terminal closed. Start a new workflow run to reconnect.';
      input.dispose();
      resize.dispose();
      observer.disconnect();
    };
    window.addEventListener('pagehide', () => socket.close(), { once: true });
  } catch (error) {
    secret.value = '';
    status.className = 'disconnected';
    status.textContent = error.message;
    button.disabled = false;
  }
});
