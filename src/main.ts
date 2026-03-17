// src/main.ts — Bunny Hole: wires all modules into a single-page app

import { resolveView } from './ui.ts';
import { encryptPassword, decryptPassword } from './crypto-password.ts';
import { encryptForRecipient, decryptAsRecipient, deriveKeyPairFromSecret, exportPublicKey, importPublicKey } from './crypto-passkey.ts';
import { registerPasskey, getPrfSecret } from './webauthn.ts';
import { getContacts, addContact, removeContact, renameContact } from './contacts.ts';
import { toBase64url, fromBase64url, encodePayload } from './encoding.ts';
// QR loaded lazily — only needed for public key sharing
import { encryptChunksPassword, encryptChunksPasskey, decryptChunkPassword, decryptChunkPasskey, CHUNK_DATA_SIZE } from './crypto-chunked.ts';
import { shouldCompress, compressImage, fileToUint8Array, type ImageQuality } from './compress.ts';
import { saveChunk, getProgress, isComplete, assembleFile, clearGroup, cleanOldChunks } from './chunk-store.ts';

const app = () => document.getElementById('app')!;
// Max text message size. Produces URLs ~60K chars — within Firefox's ~65K limit.
const MAX_MESSAGE_BYTES = 44_000;
const CREDENTIAL_KEY = 'bh_credential_id';

let pendingFile: { data: Uint8Array; mimeType: string; name: string; originalSize: number; compressedSize: number } | null = null;

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
    case 'decrypt-chunk-password': return renderDecryptChunkPassword(view.fragment);
    case 'decrypt-chunk-passkey': return renderDecryptChunkPasskey(view.fragment);
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
    <textarea id="msg" placeholder="Your message"></textarea>
    <div class="row"><small id="charcount">0 / ${MAX_MESSAGE_BYTES}</small></div>
    <hr>
    <div class="row">
      <input type="file" id="file-input">
      <select id="img-quality" class="hidden">
        <option value="high">Quality: High</option>
        <option value="medium">Quality: Medium</option>
        <option value="low">Quality: Low</option>
      </select>
      <button id="clear-file" class="hidden">Clear</button>
    </div>
    <div id="file-info" class="hidden"></div>
    <hr>
    <b>Send via</b>
    <div class="row">
      <label><input type="radio" name="mode" value="password" checked> Password</label>
      <label><input type="radio" name="mode" value="passkey" ${contacts.length > 0 ? '' : 'disabled'}> Passkey${contacts.length > 0 ? '' : ' (add contacts first)'}</label>
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

  // File attachment
  const fileInput = document.getElementById('file-input') as HTMLInputElement;
  fileInput.addEventListener('change', handleFileSelect);
  const qualitySelect = document.getElementById('img-quality') as HTMLSelectElement;
  qualitySelect.addEventListener('change', handleFileSelect);
  $('#clear-file').addEventListener('click', () => {
    fileInput.value = '';
    pendingFile = null;
    $('#file-info').classList.add('hidden');
    $('#file-info').innerHTML = '';
    $('#clear-file').classList.add('hidden');
    qualitySelect.classList.add('hidden');
    msgEl.classList.remove('hidden');
    ($('#charcount')).parentElement!.classList.remove('hidden');
  });

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

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function handleFileSelect(): Promise<void> {
  const fileInput = document.getElementById('file-input') as HTMLInputElement;
  const file = fileInput.files?.[0];
  if (!file) return;

  const msgEl = document.getElementById('msg') as HTMLTextAreaElement;
  msgEl.classList.add('hidden');
  ($('#charcount')).parentElement!.classList.add('hidden');
  $('#clear-file').classList.remove('hidden');

  const qualitySel = document.getElementById('img-quality') as HTMLSelectElement;
  const isImage = shouldCompress(file);
  if (isImage) {
    qualitySel.classList.remove('hidden');
  } else {
    qualitySel.classList.add('hidden');
  }

  const infoDiv = $('#file-info');
  infoDiv.classList.remove('hidden');
  infoDiv.innerHTML = '<p>Processing file...</p>';

  try {
    if (isImage) {
      const quality = qualitySel.value as ImageQuality;
      const result = await compressImage(file, quality);
      pendingFile = {
        data: result.data,
        mimeType: result.mimeType,
        name: file.name,
        originalSize: result.originalSize,
        compressedSize: result.compressedSize,
      };
      const chunks = Math.ceil(result.compressedSize / CHUNK_DATA_SIZE);
      infoDiv.innerHTML = `
        <p><b>${escapeHtml(file.name)}</b></p>
        <p>Compressed: ${formatSize(result.originalSize)} → ${formatSize(result.compressedSize)}</p>
        <p>Type: ${escapeHtml(result.mimeType)}, Chunks: ${chunks}</p>
        ${result.compressedSize > 250_000 ? '<p class="warn">Large file — many links will be generated.</p>' : ''}
      `;
    } else {
      const data = await fileToUint8Array(file);
      const mimeType = file.type || 'application/octet-stream';
      pendingFile = {
        data,
        mimeType,
        name: file.name,
        originalSize: file.size,
        compressedSize: file.size,
      };
      const chunks = Math.ceil(data.length / CHUNK_DATA_SIZE);
      infoDiv.innerHTML = `
        <p><b>${escapeHtml(file.name)}</b></p>
        <p>Size: ${formatSize(file.size)}</p>
        <p>Type: ${escapeHtml(mimeType)}, Chunks: ${chunks}</p>
        ${file.size > 250_000 ? '<p class="warn">Large file — many links will be generated.</p>' : ''}
      `;
    }
  } catch (e: any) {
    infoDiv.innerHTML = `<p class="err">${escapeHtml(e.message)}</p>`;
    pendingFile = null;
  }
}

async function handleEncrypt(): Promise<void> {
  // File mode
  if (pendingFile) {
    return handleEncryptFile();
  }

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

async function handleEncryptFile(): Promise<void> {
  if (!pendingFile) return;
  const mode = (document.querySelector('input[name="mode"]:checked') as HTMLInputElement)?.value;
  try {
    let fragments: string[];
    let isPasswordMode = false;

    if (mode === 'password') {
      const password = (document.getElementById('password') as HTMLInputElement).value;
      if (!password) { showResult('<p class="err">Enter a password.</p>'); return; }
      fragments = await encryptChunksPassword(pendingFile.data, pendingFile.mimeType, password);
      isPasswordMode = true;
    } else {
      const pubkeyB64 = (document.getElementById('recipient') as HTMLSelectElement).value;
      const pubkeyRaw = fromBase64url(pubkeyB64);
      const pubkey = await importPublicKey(pubkeyRaw);
      fragments = await encryptChunksPasskey(pendingFile.data, pendingFile.mimeType, pubkey);
    }

    const urls = fragments.map(f => `${location.origin}${location.pathname}#${f}`);
    showResult(`
      <hr>
      <b>Generated ${urls.length} encrypted link${urls.length > 1 ? 's' : ''}</b>
      <textarea id="result-links" readonly rows="8">${escapeHtml(urls.join('\n'))}</textarea>
      <button id="copy-all">Copy all</button>
      <p class="warn">Send all links to the recipient. Order doesn't matter.</p>
      ${isPasswordMode ? '<p class="warn">Password mode: send password separately.</p>' : ''}
    `);
    $('#copy-all').addEventListener('click', () => {
      const linksArea = document.getElementById('result-links') as HTMLTextAreaElement;
      navigator.clipboard.writeText(linksArea.value);
      ($('#copy-all') as HTMLButtonElement).textContent = 'Copied!';
    });
    pendingFile = null;
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
    section.innerHTML = '<button id="register-btn">Register passkey</button><p><small>Register to receive passkey-encrypted messages. Not needed for sending.</small></p>';
    $('#register-btn').addEventListener('click', handleRegister);
  } else {
    section.innerHTML = `
      <p>Passkey registered.</p>
      <div class="row">
        <input type="text" id="my-label" placeholder="Your name / label" value="Anonymous">
        <button id="show-pubkey-btn">Show my public key</button>
      </div>
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

    const label = (document.getElementById('my-label') as HTMLInputElement)?.value.trim() || 'Anonymous';

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
      const { renderQR } = await import('./qr.ts');
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
      <span class="contact-label">${escapeHtml(c.label)}</span>
      <code>${c.pubkey.slice(0, 8)}...</code>
      <button class="rename-contact" data-key="${escapeHtml(c.pubkey)}" data-label="${escapeHtml(c.label)}">edit</button>
      <button class="del-contact" data-key="${escapeHtml(c.pubkey)}">x</button>
    </div>
  `).join('');
  section.querySelectorAll('.rename-contact').forEach(btn => {
    btn.addEventListener('click', () => {
      const el = btn as HTMLElement;
      const pubkey = el.dataset.key!;
      const oldLabel = el.dataset.label!;
      const newLabel = prompt('Rename contact:', oldLabel);
      if (newLabel && newLabel.trim() && newLabel.trim() !== oldLabel) {
        renameContact(pubkey, newLabel.trim());
        render();
      }
    });
  });
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

// ─── Decrypt Chunk Password View ───

function renderDecryptChunkPassword(fragment: string): void {
  app().innerHTML = `
    <p>You received a file chunk.</p>
    <p>Mode: <b>Password</b></p>
    <input type="password" id="dec-password" placeholder="Enter password">
    <button id="dec-btn">Decrypt &amp; save chunk</button>
    <div id="dec-result" class="hidden"></div>
    <hr>
    <button id="new-msg-btn">New message</button>
  `;

  $('#dec-btn').addEventListener('click', async () => {
    const password = (document.getElementById('dec-password') as HTMLInputElement).value;
    try {
      const meta = await decryptChunkPassword(fragment, password);
      await saveChunk(meta);
      const groupId = toBase64url(meta.groupId);
      const progress = await getProgress(groupId);
      const resultDiv = $('#dec-result');

      if (await isComplete(groupId)) {
        const file = await assembleFile(groupId);
        resultDiv.innerHTML = renderFileReady(groupId, file!.mimeType, file!.blob.size, progress);
        attachFileReadyHandlers(groupId, file!.blob, file!.mimeType);
      } else {
        resultDiv.innerHTML = `
          <hr>
          <p>Chunk ${meta.chunkIndex + 1} of ${meta.totalChunks} saved. Progress: ${progress.have}/${progress.total}</p>
          <p>Missing chunks: ${progress.missing.map(i => i + 1).join(', ')}</p>
        `;
      }
      resultDiv.classList.remove('hidden');
    } catch {
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = '<p class="err">Decryption failed. Wrong password or corrupted link.</p>';
      resultDiv.classList.remove('hidden');
    }
  });

  $('#new-msg-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

// ─── Decrypt Chunk Passkey View ───

function renderDecryptChunkPasskey(fragment: string): void {
  app().innerHTML = `
    <p>You received a file chunk.</p>
    <p>Mode: <b>Passkey</b></p>
    <button id="dec-btn">Decrypt &amp; save chunk</button>
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
      const meta = await decryptChunkPasskey(fragment, secret);
      await saveChunk(meta);
      const groupId = toBase64url(meta.groupId);
      const progress = await getProgress(groupId);
      const resultDiv = $('#dec-result');

      if (await isComplete(groupId)) {
        const file = await assembleFile(groupId);
        resultDiv.innerHTML = renderFileReady(groupId, file!.mimeType, file!.blob.size, progress);
        attachFileReadyHandlers(groupId, file!.blob, file!.mimeType);
      } else {
        resultDiv.innerHTML = `
          <hr>
          <p>Chunk ${meta.chunkIndex + 1} of ${meta.totalChunks} saved. Progress: ${progress.have}/${progress.total}</p>
          <p>Missing chunks: ${progress.missing.map(i => i + 1).join(', ')}</p>
        `;
      }
      resultDiv.classList.remove('hidden');
    } catch {
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = '<p class="err">Decryption failed. Wrong passkey or corrupted link.</p>';
      resultDiv.classList.remove('hidden');
    }
  });

  $('#new-msg-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

// ─── File Ready helpers ───

function renderFileReady(
  groupId: string,
  mimeType: string,
  size: number,
  progress: { have: number; total: number },
): string {
  const canPreview = mimeType.startsWith('image/') || mimeType.startsWith('audio/') || mimeType.startsWith('video/');
  return `
    <hr>
    <p><b>File ready!</b></p>
    <p>Chunks: ${progress.have}/${progress.total}</p>
    <p>Type: ${escapeHtml(mimeType)}, Size: ${formatSize(size)}</p>
    <button id="download-btn">Download</button>
    ${canPreview ? '<button id="preview-btn">Preview</button>' : ''}
    <button id="clear-chunks-btn">Clear chunks</button>
    <div id="preview-area"></div>
  `;
}

function attachFileReadyHandlers(groupId: string, blob: Blob, mimeType: string): void {
  $('#download-btn').addEventListener('click', () => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    // Derive a filename from the mime type
    const ext = mimeType.split('/')[1]?.split(';')[0] || 'bin';
    a.download = `file.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  const previewBtn = document.getElementById('preview-btn');
  if (previewBtn) {
    previewBtn.addEventListener('click', () => {
      const area = $('#preview-area');
      // Revoke any previous object URL
      const existing = area.querySelector('[src]') as HTMLMediaElement | HTMLImageElement | null;
      if (existing) URL.revokeObjectURL(existing.src);
      const url = URL.createObjectURL(blob);
      if (mimeType.startsWith('image/')) {
        area.innerHTML = `<img src="${url}" style="max-width:100%">`;
      } else if (mimeType.startsWith('audio/')) {
        area.innerHTML = `<audio controls src="${url}"></audio>`;
      } else if (mimeType.startsWith('video/')) {
        area.innerHTML = `<video controls src="${url}" style="max-width:100%"></video>`;
      }
    });
  }

  $('#clear-chunks-btn').addEventListener('click', async () => {
    await clearGroup(groupId);
    ($('#clear-chunks-btn') as HTMLButtonElement).textContent = 'Cleared!';
    ($('#clear-chunks-btn') as HTMLButtonElement).disabled = true;
  });
}

// ─── Add Contact View ───

function renderAddContact(pubkey: string, label: string): void {
  app().innerHTML = `
    <p>Someone shared their public key with you.</p>
    <div class="row">
      <b>Label:</b>
      <input type="text" id="contact-label" value="${escapeHtml(label)}" placeholder="Contact name">
    </div>
    <p><b>Key:</b> <code>${pubkey.slice(0, 16)}...${pubkey.slice(-8)}</code></p>
    <button id="add-btn">Add to contacts</button>
    <button id="back-btn">Back</button>
    <div id="add-result"></div>
  `;

  $('#add-btn').addEventListener('click', () => {
    const finalLabel = (document.getElementById('contact-label') as HTMLInputElement).value.trim() || label;
    try {
      addContact(finalLabel, pubkey);
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
cleanOldChunks().catch(() => {});
