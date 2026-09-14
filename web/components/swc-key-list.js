import { createRecord, deleteRecord, listRecords } from '../lib/pds.js';

// The record the SSH server reads: a badgeBlueKeys association of service
// requester_associate, whose challenge is the account and whose keyId is the
// OpenSSH public key with its comment stripped. Same shape the polyrepo's
// market policies use for the same association type.
const BADGE_BLUE_KEYS_NSID = 'com.publicdomainrelay.temp.badgeBlueKeys';
const REQUESTER_ASSOCIATE = 'requester_associate';

function parsePublicKey(text) {
  const parts = String(text).trim().split(/\s+/);
  if (parts.length < 2) return null;
  if (!/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)$/.test(parts[0])) return null;
  if (!/^[A-Za-z0-9+/]+=*$/.test(parts[1])) return null;
  return { algo: parts[0], key: parts[1], comment: parts.slice(2).join(' ') };
}

export class SwcKeyList extends HTMLElement {
  start(client, session) {
    this._client = client;
    this._session = session;
    this._keys = [];
    this.render();
    this._load();
  }

  render() {
    this.innerHTML = `
      <div class="header-row">
        <h2>SSH keys</h2>
        <button class="add-btn" id="add" title="Add an SSH key" aria-label="Add an SSH key">+</button>
      </div>
      <p class="subheader">Keys here can open a session; each one gets its own VM.</p>
      <div id="key-list"><p class="help">Loading…</p></div>
      <div id="add-modal" class="modal-backdrop hidden">
        <div class="modal-card">
          <h2>Add an SSH key</h2>
          <p class="help mt-3">Paste your public key — the contents of <code>~/.ssh/id_ed25519.pub</code>.</p>
          <div class="mt-3">
            <input type="text" id="key-name" placeholder="label (e.g. laptop)" autocomplete="off">
          </div>
          <div class="mt-3">
            <textarea id="key-value" placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... you@host" spellcheck="false"></textarea>
          </div>
          <p id="add-error" class="text-danger mt-3 hidden" style="font-size:13px;"></p>
          <div class="mt-3" style="display:flex;gap:10px;">
            <button class="btn btn-primary" id="add-save" style="flex:1;">Register key</button>
            <button class="btn btn-outline" id="add-cancel">Cancel</button>
          </div>
        </div>
      </div>`;

    this.querySelector('#add').addEventListener('click', () => this._openAdd());
    this.querySelector('#add-cancel').addEventListener('click', () => this._closeAdd());
    this.querySelector('#add-save').addEventListener('click', () => this._save());
    this.querySelector('#key-value').addEventListener('input', () => {
      const parsed = parsePublicKey(this.querySelector('#key-value').value);
      if (parsed) this.querySelector('#key-value').style.borderColor = '';
    });
  }

  async _load() {
    const list = this.querySelector('#key-list');
    try {
      const records = await listRecords(this._client, BADGE_BLUE_KEYS_NSID);
      this._keys = records.filter((r) => this._isAssociation(r.value)).map((r) => ({
        rkey: r.uri.split('/').pop(),
        name: r.value.name || 'unnamed',
        keyId: String(r.value.keyId || ''),
      }));
      this._renderList();
    } catch (err) {
      list.innerHTML = `<p class="text-danger" style="font-size:13px;">Could not read your keys: ${this._esc(err.message || err)}</p>`;
    }
  }

  _isAssociation(value) {
    return value
      && value.service === REQUESTER_ASSOCIATE
      && value.challenge === this._session.userDid;
  }

  _renderList() {
    const list = this.querySelector('#key-list');
    if (this._keys.length === 0) {
      list.innerHTML = '<div class="card"><p class="help">No SSH keys registered yet. Add one to get started.</p></div>';
      return;
    }
    list.innerHTML = this._keys.map((k) => `
      <div class="card key-card">
        <div class="name-row">
          <strong>${this._esc(k.name)}</strong>
          <span class="chip chip-requester-associate">requester_associate</span>
        </div>
        <div class="key-code"><span>${this._esc(k.keyId)}</span></div>
        <div class="actions">
          <button class="act-danger" data-remove="${this._esc(k.rkey)}">Remove</button>
        </div>
      </div>`).join('');

    for (const button of list.querySelectorAll('[data-remove]')) {
      button.addEventListener('click', () => this._remove(button.getAttribute('data-remove')));
    }
  }

  _openAdd() {
    this._setError('');
    this.querySelector('#key-name').value = '';
    this.querySelector('#key-value').value = '';
    this.querySelector('#add-modal').classList.remove('hidden');
    this.querySelector('#key-value').focus();
  }

  _closeAdd() {
    this.querySelector('#add-modal').classList.add('hidden');
  }

  _setError(message) {
    const error = this.querySelector('#add-error');
    error.textContent = message;
    error.classList.toggle('hidden', !message);
  }

  async _save() {
    const name = this.querySelector('#key-name').value.trim();
    const raw = this.querySelector('#key-value').value;
    const parsed = parsePublicKey(raw);
    if (!parsed) {
      this._setError('That does not look like an OpenSSH public key.');
      return;
    }
    const button = this.querySelector('#add-save');
    button.disabled = true;
    button.textContent = 'Registering…';
    this._setError('');
    try {
      // keyId carries the key without its comment, which is what the SSH
      // server compares against the key the client presents.
      await createRecord(this._client, BADGE_BLUE_KEYS_NSID, {
        $type: BADGE_BLUE_KEYS_NSID,
        keyId: `${parsed.algo} ${parsed.key}`,
        name: name || parsed.comment || 'key',
        challenge: this._session.userDid,
        service: REQUESTER_ASSOCIATE,
        createdAt: new Date().toISOString(),
      });
      this._closeAdd();
      await this._load();
    } catch (err) {
      this._setError(String(err.message || err));
    } finally {
      button.disabled = false;
      button.textContent = 'Register key';
    }
  }

  async _remove(rkey) {
    try {
      await deleteRecord(this._client, BADGE_BLUE_KEYS_NSID, rkey);
      await this._load();
    } catch (err) {
      this.querySelector('#key-list').insertAdjacentHTML(
        'afterbegin',
        `<p class="text-danger" style="font-size:13px;">Could not remove: ${this._esc(err.message || err)}</p>`,
      );
    }
  }

  _esc(value) {
    return String(value).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }
}

customElements.define('swc-key-list', SwcKeyList);
