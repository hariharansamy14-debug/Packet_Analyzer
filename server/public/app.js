const samplePacket = `aa bb cc dd ee ff 11 22 33 44 55 66 08 00
45 00 00 28 12 34 40 00 40 06 00 00 c0 a8 01 0a
c0 a8 01 14 c3 50 01 bb 00 00 00 01 00 00 00 00
50 02 72 10 00 00 00 00`;

let input;
let results;
let error;
let byteCount;
let packetSize;

if (typeof document === 'undefined') {
  console.info('Packet analyzer running without a browser document.');
} else {
  const form = document.querySelector('#packet-form');
  input = document.querySelector('#hex-input');
  results = document.querySelector('#results');
  error = document.querySelector('#error');
  byteCount = document.querySelector('#byte-count');
  packetSize = document.querySelector('#packet-size');

  input.addEventListener('input', updateByteCount);
  document.querySelector('#sample-button').addEventListener('click', () => {
    input.value = samplePacket;
    updateByteCount();
  });
  form.addEventListener('submit', analyze);
  updateByteCount();
}

function cleanHex(value) {
  return value.replace(/\s+/g, '');
}

function updateByteCount() {
  const hex = cleanHex(input.value);
  byteCount.textContent = `${hex.length / 2 || 0} bytes`;
}

function displayValue(value) {
  if (value === null || value === undefined) return 'Not present';
  if (typeof value === 'object' && 'length' in value) return `${value.length} bytes`;
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  return String(value);
}

function layerMarkup(title, data, open = false) {
  if (!data) return '';
  const fields = Object.entries(data)
    .filter(([, value]) => value === null || typeof value !== 'object' || 'length' in value)
    .map(([key, value]) => `<div class="field"><small>${key.replace(/[A-Z]/g, letter => ` ${letter}`).toUpperCase()}</small><strong>${displayValue(value)}</strong></div>`)
    .join('');
  return `<details class="layer" ${open ? 'open' : ''}><summary>${title}</summary><div class="layer-content">${fields}</div></details>`;
}

function renderPacket(packet, bytes, id) {
  const network = packet.network;
  const transport = packet.transport;
  const protocol = network?.protocol || packet.ethernet?.protocol || 'Unknown';
  packetSize.textContent = `${bytes} bytes / ${protocol} · saved #${id}`;
  results.className = 'layer-list';
  results.innerHTML = [
    layerMarkup('Ethernet · Layer 2', packet.ethernet, true),
    layerMarkup('IPv4 · Layer 3', network, true),
    layerMarkup(`${protocol} · Layer 4`, transport, true)
  ].join('') || '<div class="empty-state"><p>No decodable layers found.</p></div>';
}

async function analyze(event) {
  event.preventDefault();
  error.hidden = true;
  const hex = cleanHex(input.value);
  if (!hex) {
    error.textContent = 'Enter a packet before analyzing.';
    error.hidden = false;
    return;
  }

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hex })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to analyze packet.');
    renderPacket(data.packet, data.bytes, data.id);
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  }
}

