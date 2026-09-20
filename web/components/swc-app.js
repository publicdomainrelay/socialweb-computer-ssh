import { completeLogin, startLogin, isLocalhost, pendingLogin } from '../lib/atproto-oauth.js';
import { createPdsClient, clearSession, depositSession, loadSession, saveSession } from '../lib/pds.js';
import { OAUTH_SCOPE } from '../generated/oauth-scope.js';
import './swc-key-list.js';
import './swc-pair.js';

const RETURN_KEY = 'swc-return-to';

export class SwcApp extends HTMLElement {
  connectedCallback() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');

    if (code && state) {
      this._finishLogin(code, state);
      return;
    }
    if (params.get('error')) {
      const session = loadSession();
      window.history.replaceState({}, '', window.location.pathname);
      if (session) return this._renderKeys(session);
      return this._renderLogin(`Sign-in failed: ${params.get('error_description') || params.get('error')}`, params.get('error'));
    }
    if (params.get('error')) window.history.replaceState({}, '', window.location.pathname);

    const session = loadSession();
    if (session) this._renderKeys(session);
    else this._renderLogin();
  }

  _renderLogin(error) {
    const localhost = isLocalhost();
    this.innerHTML = `
      <main class="app-shell">
        <header class="header-row">
          <h1>socialweb<span class="text-muted">-computer-ssh</span></h1>
        </header>
        <p class="subheader">
          Register an SSH key against your Atmosphere account, then <code>ssh</code> in and your
          command runs in a fresh compute market VM.
        </p>

        <div class="card">
          <h2>Sign in</h2>
          <form id="login-form" class="mt-3">
            <p class="help mb-3">Enter your handle to authenticate.</p>
            <input type="text" id="handle" name="handle" placeholder="alice.example.com"
              autocomplete="username" autocapitalize="none" spellcheck="false" required>
            <button type="submit" class="btn btn-primary btn-block mt-3" id="login-submit">Sign in with the Atmosphere</button>
          </form>
          <button id="bsky-btn" class="btn btn-secondary btn-block mt-3">Sign in with Bluesky Social</button>
          <p id="login-error" class="text-danger mt-3 ${error ? '' : 'hidden'}" style="font-size:13px;">${this._esc(error || '')}</p>
          ${localhost ? '' : '<p class="help mt-3">Your PDS will ask you to approve this app.</p>'}
        </div>

        <nav class="text-center mt-3" style="font-size:13px;">
          <a href="https://github.com/publicdomainrelay/socialweb-computer-ssh" target="_blank" rel="noopener" class="text-muted">Source Code</a>
        </nav>
      </main>`;

    const form = this.querySelector('#login-form');
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      this._beginLogin(this.querySelector('#handle').value.trim());
    });
    this.querySelector('#bsky-btn').addEventListener('click', () => this._beginLogin('bsky.social'));
  }

  async _beginLogin(handle) {
    const button = this.querySelector('#login-submit');
    const error = this.querySelector('#login-error');
    error.classList.add('hidden');
    if (!handle) {
      error.textContent = 'Enter your handle.';
      error.classList.remove('hidden');
      return;
    }
    button.disabled = true;
    button.textContent = 'Redirecting to your PDS…';
    sessionStorage.setItem(RETURN_KEY, JSON.stringify({ at: Date.now() }));
    try {
      window.location.href = await startLogin(handle, OAUTH_SCOPE, null);
    } catch (err) {
      button.disabled = false;
      button.textContent = 'Sign in with the Atmosphere';
      error.textContent = String(err.message || err);
      error.classList.remove('hidden');
    }
  }

  async _finishLogin(code, state) {
    this.innerHTML = '<main class="app-shell"><div class="card text-center"><p class="text-muted">Completing sign-in…</p></div></main>';
    try {
      const { session } = await completeLogin(code, state);
      saveSession(session);
      // The SSH server holds its own copy of the session so it can hand one to
      // the requester process; it never writes to the account.
      await depositSession(session);
      window.history.replaceState({}, '', window.location.pathname);
      this._renderKeys(session);
    } catch (err) {
      window.history.replaceState({}, '', window.location.pathname);
      this._renderLogin(`Sign-in failed: ${err.message || err}`);
    }
  }

  async _renderKeys(session) {
    const client = createPdsClient(session);
    // Which name to ssh to is the server's to say: more than one can reach this
    // door (an apex domain on the same address, for instance), and the page would
    // otherwise offer whichever one it happens to be served from.
    const sshHost = await this._sshHost();
    this.innerHTML = `
      <main class="app-shell">
        <header class="header-row">
          <h1>socialweb<span class="text-muted">-computer-ssh</span></h1>
          <button class="btn btn-outline btn-sm" id="sign-out">Sign out</button>
        </header>
        <p class="subheader">Signed in as <code>@${this._esc(session.handle || session.userDid)}</code></p>
        <div class="card mt-3">
          <h3>Connect</h3>
          <p class="help mt-3">Once a key is registered:</p>
          <div class="key-code mt-3">ssh ${this._esc(session.handle || session.userDid)}@${this._esc(sshHost)}</div>
          <p class="help mt-3">Anything you pass as <code>LC_*</code> travels to the VM, and picks the
          fulfillment policy:</p>
          <div class="key-code mt-3">LC_MY_VAR=hello ssh ${this._esc(session.handle || session.userDid)}@${this._esc(sshHost)} "echo \$LC_MY_VAR"</div>
        </div>
        <swc-key-list id="keys"></swc-key-list>
        <swc-pair id="pair"></swc-pair>
        <nav class="text-center mt-3" style="font-size:13px;">
          <a href="https://github.com/publicdomainrelay/socialweb-computer-ssh" target="_blank" rel="noopener" class="text-muted">Source Code</a>
        </nav>
      </main>`;

    this.querySelector('#sign-out').addEventListener('click', () => {
      clearSession();
      this._renderLogin();
    });
    this.querySelector('#keys').start(client, session);
    this.querySelector('#pair').start(session);
  }

  async _sshHost() {
    try {
      const res = await fetch('/connect.json');
      if (res.ok) {
        const { sshHost } = await res.json();
        if (typeof sshHost === 'string' && sshHost) return sshHost;
      }
    } catch { /* fall back to where we were served from */ }
    return window.location.hostname;
  }

  _esc(value) {
    return String(value).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }
}

customElements.define('swc-app', SwcApp);
