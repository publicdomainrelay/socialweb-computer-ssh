import { cocorePairPoll, cocorePairStart, cocoreStatus } from '../lib/cocore-pair.js';
import { clearSession } from '../lib/pds.js';

// co/core inference, started as part of the signed-in view.
//
// Folded into the sign-in rather than bolted on: a signed-in account with no
// co/core token is an account whose VMs have no inference, so the pairing begins
// on its own and the page shows the code to approve. Conditional, not mandatory:
// a token is minted once per account and stored, so an account that already has
// one is never walked through this again.
export class SwcPair extends HTMLElement {
  async start(session) {
    this._session = session;
    this._timer = null;
    this.render();
    await this._refresh();
  }

  disconnectedCallback() {
    this._stopPolling();
  }

  render() {
    this.innerHTML = `
      <div class="card mt-3">
        <h2>co/core inference</h2>
        <div id="pair-body"><p class="help mt-3">Loading…</p></div>
      </div>`;
  }

  async _refresh() {
    try {
      const status = await cocoreStatus(this._session);
      if (status.paired) {
        this._renderPaired(status);
        return;
      }
      // No token for this account, so the pairing begins here rather than
      // behind a button: the whole point of showing this after a sign-in is
      // that the VM is otherwise left without inference. Nothing is asked of
      // the user that the flow does not already need.
      await this._begin();
    } catch (err) {
      if (err.status === 401) {
        this._renderExpired();
        return;
      }
      this._renderMessage(`Could not reach the pairing service: ${this._esc(err.message || err)}`);
    }
  }

  _renderMessage(html) {
    this.querySelector('#pair-body').innerHTML = html;
  }

  /**
   * The session the page holds has aged out. The server proves a deposit with a
   * live call to the account's PDS, so an expired access token is a refusal
   * rather than a bug -- and the only way forward is a fresh sign-in.
   */
  _renderExpired() {
    this._renderMessage(`
      <p class="help mt-3">Your session has expired, so co/core cannot be connected yet.</p>
      <div class="mt-3"><button class="btn btn-primary" id="pair-relogin">Sign in again</button></div>`);
    this.querySelector('#pair-relogin').addEventListener('click', () => {
      clearSession();
      window.location.reload();
    });
  }

  _renderPaired(status) {
    const when = status.pairedAt ? new Date(status.pairedAt).toLocaleDateString() : 'earlier';
    this._renderMessage(`
      <p class="help mt-3">Connected${status.accountDid ? ` as <code>${this._esc(status.accountDid)}</code>` : ''} on ${this._esc(when)}.</p>
      <p class="help mt-3">Every VM you open gets this token at
      <code>/root/.pi/agent/cocore-config.json</code>, billed to your co/core account.</p>
      <div class="mt-3"><button class="btn btn-outline btn-sm" id="pair-again">Connect a different account</button></div>`);
    this.querySelector('#pair-again').addEventListener('click', () => this._begin());
  }

  /**
   * The retry affordance, reached only when the automatic attempt failed --
   * a declined approval, an expired code, or a pairing co/core refused. Never
   * the first thing a signed-in account sees.
   */
  _renderIdle() {
    this._renderMessage(`
      <p class="help mt-3">Every VM gets a co/core inference token, spent from your own
      credits rather than the operator's.</p>
      <div class="mt-3"><button class="btn btn-primary" id="pair-start">Try again</button></div>
      <p class="help mt-3" id="pair-error"></p>`);
    this.querySelector('#pair-start').addEventListener('click', () => this._begin());
  }

  async _begin() {
    const button = this.querySelector('#pair-start');
    if (button) {
      button.disabled = true;
      button.textContent = 'Starting…';
    }
    try {
      const started = await cocorePairStart(this._session);
      this._renderPending(started);
      this._poll(started);
    } catch (err) {
      this._renderError(String(err.message || err));
    }
  }

  _renderPending({ userCode, verificationUri }) {
    this._renderMessage(`
      <p class="help mt-3">Approve this code at co/core:</p>
      <div class="key-code mt-3"><span>${this._esc(userCode || '(no code returned)')}</span></div>
      <p class="mt-3"><a href="${this._esc(verificationUri)}" target="_blank" rel="noopener">${this._esc(verificationUri)}</a></p>
      <p class="help mt-3" id="pair-status">Waiting for approval…</p>`);
  }

  _renderError(message) {
    this._renderIdle();
    const error = this.querySelector('#pair-error');
    if (error) error.textContent = message;
  }

  _poll({ pairId, intervalSecs }) {
    this._stopPolling();
    const every = Math.max(1, Number(intervalSecs) || 5) * 1000;
    const tick = async () => {
      try {
        const { status } = await cocorePairPoll(pairId);
        if (status === 'complete') {
          this._stopPolling();
          await this._refresh();
          return;
        }
        if (status === 'denied' || status === 'expired') {
          this._stopPolling();
          this._renderError(
            status === 'denied' ? 'That request was denied at co/core.' : 'That code expired before it was approved.',
          );
          return;
        }
        const line = this.querySelector('#pair-status');
        if (line) line.textContent = 'Waiting for approval…';
      } catch (err) {
        this._stopPolling();
        this._renderError(String(err.message || err));
        return;
      }
      this._timer = setTimeout(tick, every);
    };
    this._timer = setTimeout(tick, every);
  }

  _stopPolling() {
    if (this._timer !== null) {
      clearTimeout(this._timer);
      this._timer = null;
    }
  }

  _esc(value) {
    return String(value).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }
}

customElements.define('swc-pair', SwcPair);
