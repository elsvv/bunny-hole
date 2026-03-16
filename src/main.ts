// src/main.ts — Bunny Hole: wires all modules into a single-page app

import { resolveView } from './ui.ts';
import { encryptPassword, decryptPassword } from './crypto-password.ts';
import { encryptForRecipient, decryptAsRecipient, deriveKeyPairFromSecret, exportPublicKey, importPublicKey } from './crypto-passkey.ts';
import { registerPasskey, getPrfSecret } from './webauthn.ts';
import { getContacts, addContact, removeContact } from './contacts.ts';
import { toBase64url, fromBase64url, encodePayload } from './encoding.ts';
import { renderQR } from './qr.ts';

const app = () => document.getElementById('app')!;
const MAX_MESSAGE_BYTES = 24_000;
const CREDENTIAL_KEY = 'bh_credential_id';

function getCredentialId(): string | null {
  return localStorage.getItem(CREDENTIAL_KEY);
}

function render(): void {
  const view = resolveView();
  switch (view.kind) {
    case 'compose': return renderCompose();
    case 'decrypt-password': return renderDecryptPassword(view.fragment);
    case 'decrypt-passkey': return renderDecryptPasskey(view.fragment);
    case 'add-contact': return renderAddContact(view.pubkey, view.label);
  }
}

function $(sel: string): HTMLElement {
  return document.querySelector(sel) as HTMLElement;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── Compose View ───

function renderCompose(): void {
  const hasPasskey = !!getCredentialId();
  const contacts = getContacts();

  app().innerHTML = `
    <textarea id="msg" placeholder="Your message" maxlength="${MAX_MESSAGE_BYTES}"></textarea>
    <div class="row"><small id="charcount">0 / ${MAX_MESSAGE_BYTES}</small></div>
    <hr>
    <b>Send via</b>
    <div class="row">
      <label><input type="radio" name="mode" value="password" checked> Password</label>
      <label><input type="radio" name="mode" value="passkey" ${hasPasskey ? '' : 'disabled'}> Passkey${hasPasskey ? '' : ' (register first)'}</label>
    </div>
    <div id="mode-fields"></div>
    <button id="encrypt-btn">Encrypt</button>
    <div id="result" class="hidden"></div>
    <hr>
    <b>My Keys</b>
    <div id="keys-section"></div>
    <hr>
    <b>Contacts</b>
    <div id="contacts-section"></div>
    <div class="row">
      <input type="text" id="new-label" placeholder="Label">
      <input type="text" id="new-pubkey" placeholder="Public key">
      <button id="add-contact-btn">Add</button>
    </div>
  `;

  // Character counter
  const msgEl = document.getElementById('msg') as HTMLTextAreaElement;
  msgEl.addEventListener('input', () => {
    const len = new TextEncoder().encode(msgEl.value).length;
    ($('#charcount')).textContent = `${len} / ${MAX_MESSAGE_BYTES}`;
  });

  // Mode radio toggle
  document.querySelectorAll('input[name="mode"]').forEach(el =>
    el.addEventListener('change', updateModeFields)
  );
  updateModeFields();

  // Encrypt button
  $('#encrypt-btn').addEventListener('click', handleEncrypt);

  // Keys section
  renderKeysSection(hasPasskey);

  // Contacts section
  renderContactsList(contacts);
  $('#add-contact-btn').addEventListener('click', handleAddContact);
}

function updateModeFields(): void {
  const mode = (document.querySelector('input[name="mode"]:checked') as HTMLInputElement)?.value;
  const container = $('#mode-fields');
  if (mode === 'password') {
    container.innerHTML = '<input type="password" id="password" placeholder="Encryption password">';
  } else {
    const contacts = getContacts();
    if (contacts.length === 0) {
      container.innerHTML = '<p class="err">No contacts. Add a recipient\'s public key first.</p>';
    } else {
      container.innerHTML = `<select id="recipient">${contacts.map(c =>
        `<option value="${c.pubkey}">${escapeHtml(c.label)}</option>`
      ).join('')}</select>`;
    }
  }
}

async function handleEncrypt(): Promise<void> {
  const msg = (document.getElementById('msg') as HTMLTextAreaElement).value;
  if (!msg) return;

  const msgBytes = new TextEncoder().encode(msg).length;
  if (msgBytes > MAX_MESSAGE_BYTES) {
    showResult(`<p class="err">Message too large (${msgBytes} bytes, max ${MAX_MESSAGE_BYTES}).</p>`);
    return;
  }

  const mode = (document.querySelector('input[name="mode"]:checked') as HTMLInputElement)?.value;
  try {
    let fragment: string;
    let isPasswordMode = false;

    if (mode === 'password') {
      const password = (document.getElementById('password') as HTMLInputElement).value;
      if (!password) { showResult('<p class="err">Enter a password.</p>'); return; }
      fragment = await encryptPassword(msg, password);
      isPasswordMode = true;
    } else {
      const pubkeyB64 = (document.getElementById('recipient') as HTMLSelectElement).value;
      const pubkeyRaw = fromBase64url(pubkeyB64);
      const pubkey = await importPublicKey(pubkeyRaw);
      fragment = await encryptForRecipient(msg, pubkey);
    }

    const url = `${location.origin}${location.pathname}#${fragment}`;
    showResult(`
      <hr>
      <b>Encrypted link</b>
      <div class="row">
        <input type="text" id="result-url" value="${escapeHtml(url)}" readonly>
        <button id="copy-btn">Copy</button>
      </div>
      ${isPasswordMode ? '<p class="warn">Send this link and the password separately.</p>' : ''}
    `);
    $('#copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(url);
      ($('#copy-btn') as HTMLButtonElement).textContent = 'Copied!';
    });
  } catch (e: any) {
    showResult(`<p class="err">${escapeHtml(e.message)}</p>`);
  }
}

function showResult(html: string): void {
  const resultDiv = $('#result');
  resultDiv.innerHTML = html;
  resultDiv.classList.remove('hidden');
}

// ─── Keys Section ───

function renderKeysSection(hasPasskey: boolean): void {
  const section = $('#keys-section');
  if (!hasPasskey) {
    section.innerHTML = '<button id="register-btn">Register passkey</button>';
    $('#register-btn').addEventListener('click', handleRegister);
  } else {
    section.innerHTML = `
      <p>Passkey registered.</p>
      <button id="show-pubkey-btn">Show my public key</button>
      <div id="pubkey-display" class="hidden"></div>
    `;
    $('#show-pubkey-btn').addEventListener('click', handleShowPubkey);
  }
}

async function handleRegister(): Promise<void> {
  try {
    const reg = await registerPasskey();
    if (!reg.prfSupported) {
      alert('Your browser/device does not support the PRF extension. Passkey mode will not work. Use password mode instead.');
      return;
    }
    localStorage.setItem(CREDENTIAL_KEY, reg.credentialId);
    render();
  } catch (e: any) {
    alert(`Registration failed: ${e.message}`);
  }
}

async function handleShowPubkey(): Promise<void> {
  try {
    const credId = getCredentialId()!;
    const secret = await getPrfSecret(credId);
    const kp = await deriveKeyPairFromSecret(secret);
    const pubRaw = await exportPublicKey(kp.publicKey);
    const pubB64 = toBase64url(pubRaw);

    // Prompt for label
    const label = prompt('Your name/label for this key:') || 'Anonymous';

    // Create share URL (mode 0x03)
    const shareFragment = encodePayload(0x03, pubRaw, new TextEncoder().encode(label));
    const shareUrl = `${location.origin}${location.pathname}#${shareFragment}`;

    const display = $('#pubkey-display');
    display.innerHTML = `
      <code>${pubB64}</code>
      <button id="copy-pubkey">Copy key</button>
      <hr>
      <b>Share link</b>
      <div class="row">
        <input type="text" value="${escapeHtml(shareUrl)}" readonly style="font-size:.8em">
        <button id="copy-share">Copy link</button>
      </div>
      <canvas id="qr-canvas"></canvas>
    `;
    display.classList.remove('hidden');

    $('#copy-pubkey').addEventListener('click', () => navigator.clipboard.writeText(pubB64));
    $('#copy-share').addEventListener('click', () => navigator.clipboard.writeText(shareUrl));

    // Render QR code for share URL
    try {
      const canvas = document.getElementById('qr-canvas') as HTMLCanvasElement;
      renderQR(canvas, shareUrl);
    } catch {
      // QR may fail for very long URLs, that's ok
    }
  } catch (e: any) {
    alert(`Failed to get public key: ${e.message}`);
  }
}

// ─── Contacts Section ───

function renderContactsList(contacts: ReturnType<typeof getContacts>): void {
  const section = $('#contacts-section');
  if (contacts.length === 0) {
    section.innerHTML = '<p>No contacts yet.</p>';
    return;
  }
  section.innerHTML = contacts.map(c => `
    <div class="contact">
      <span>${escapeHtml(c.label)}</span>
      <code>${c.pubkey.slice(0, 8)}...</code>
      <button class="del-contact" data-key="${escapeHtml(c.pubkey)}">x</button>
    </div>
  `).join('');
  section.querySelectorAll('.del-contact').forEach(btn =>
    btn.addEventListener('click', () => {
      removeContact((btn as HTMLElement).dataset.key!);
      render();
    })
  );
}

function handleAddContact(): void {
  const label = (document.getElementById('new-label') as HTMLInputElement).value.trim();
  const pubkey = (document.getElementById('new-pubkey') as HTMLInputElement).value.trim();
  if (!label || !pubkey) return;
  try {
    addContact(label, pubkey);
    render();
  } catch (e: any) {
    alert(e.message);
  }
}

// ─── Decrypt Password View ───

function renderDecryptPassword(fragment: string): void {
  app().innerHTML = `
    <p>You received an encrypted message.</p>
    <p>Mode: <b>Password</b></p>
    <input type="password" id="dec-password" placeholder="Enter password">
    <button id="dec-btn">Decrypt</button>
    <div id="dec-result" class="hidden"></div>
    <hr>
    <button id="new-msg-btn">New message</button>
  `;

  $('#dec-btn').addEventListener('click', async () => {
    const password = (document.getElementById('dec-password') as HTMLInputElement).value;
    try {
      const message = await decryptPassword(fragment, password);
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = `<hr><b>Decrypted message</b><pre class="msg">${escapeHtml(message)}</pre>`;
      resultDiv.classList.remove('hidden');
    } catch {
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = '<p class="err">Decryption failed. Wrong password or corrupted link.</p>';
      resultDiv.classList.remove('hidden');
    }
  });

  $('#new-msg-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

// ─── Decrypt Passkey View ───

function renderDecryptPasskey(fragment: string): void {
  app().innerHTML = `
    <p>You received an encrypted message.</p>
    <p>Mode: <b>Passkey</b></p>
    <button id="dec-btn">Decrypt with passkey</button>
    <div id="dec-result" class="hidden"></div>
    <hr>
    <button id="new-msg-btn">New message</button>
  `;

  $('#dec-btn').addEventListener('click', async () => {
    const credId = getCredentialId();
    if (!credId) {
      alert('No passkey registered on this device. Register a passkey first.');
      return;
    }
    try {
      const secret = await getPrfSecret(credId);
      const message = await decryptAsRecipient(fragment, secret);
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = `<hr><b>Decrypted message</b><pre class="msg">${escapeHtml(message)}</pre>`;
      resultDiv.classList.remove('hidden');
    } catch {
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = '<p class="err">Decryption failed. Wrong passkey or corrupted link.</p>';
      resultDiv.classList.remove('hidden');
    }
  });

  $('#new-msg-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

// ─── Add Contact View ───

function renderAddContact(pubkey: string, label: string): void {
  app().innerHTML = `
    <p>Someone shared their public key with you.</p>
    <p><b>Label:</b> ${escapeHtml(label)}</p>
    <p><b>Key:</b> <code>${pubkey.slice(0, 16)}...${pubkey.slice(-8)}</code></p>
    <button id="add-btn">Add to contacts</button>
    <button id="back-btn">Back</button>
    <div id="add-result"></div>
  `;

  $('#add-btn').addEventListener('click', () => {
    try {
      addContact(label, pubkey);
      $('#add-result').innerHTML = '<p>Contact added!</p>';
    } catch (e: any) {
      $('#add-result').innerHTML = `<p class="err">${escapeHtml(e.message)}</p>`;
    }
  });

  $('#back-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

// ─── Boot ───

window.addEventListener('hashchange', render);
render();
