'use strict';

const form = document.getElementById('connect');
const secret = document.getElementById('secret');
const status = document.getElementById('status');
const terminal = new Terminal({ cursorBlink: true });
const fit = new FitAddon.FitAddon();
terminal.loadAddon(fit);
terminal.open(document.getElementById('terminal'));
fit.fit();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = form.querySelector('button');
  button.disabled = true;
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
      status.textContent = 'Connected. Exit Bash or close this page to end the run.';
      fit.fit();
      send({ type: 'resize', cols: terminal.cols, rows: terminal.rows });
      terminal.focus();
    };
    socket.onmessage = ({ data }) => terminal.write(data);
    socket.onerror = () => { status.textContent = 'Terminal connection failed.'; };
    socket.onclose = () => {
      status.textContent = 'Terminal closed. Start a new workflow run to reconnect.';
      input.dispose();
      resize.dispose();
      observer.disconnect();
    };
    window.addEventListener('pagehide', () => socket.close(), { once: true });
  } catch (error) {
    secret.value = '';
    status.textContent = error.message;
    button.disabled = false;
  }
});
