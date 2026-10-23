// Real-browser end-to-end test of the signup flow: first admin from the
// setup link, logging in through the portal, creating a group and an
// invite, an invitee redeeming it, and logging out. It drives headless
// Chrome over the DevTools protocol with Node's built-in WebSocket, so it
// needs no npm packages. Real browsers matter here: they decide the
// Origin, Referer and cookie behaviour that the CSRF and handoff checks
// depend on, which scripted clients only imitate.
//
// Run by e2e_test.go, which starts tabs and sets CHROME, AUTH, PORTAL and
// SETUP.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { CHROME, AUTH, PORTAL, SETUP } = process.env;
const ADMIN_PW = "admin password for e2e";
const GUEST_PW = "guest password for e2e";

// The running Chrome and its profile directory, recorded the moment it's
// spawned so that every exit path (success, failure, a launch that never
// finishes, SIGTERM) can clean up through stopChrome.
let chromeProc, chromeDir;

function stopChrome() {
  return new Promise((done) => {
    const cleanup = () => {
      if (chromeDir) rmSync(chromeDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
      chromeDir = undefined;
      done();
    };
    // No pid means the spawn itself failed (bad path): nothing to kill.
    if (!chromeProc?.pid || chromeProc.exitCode !== null || chromeProc.signalCode !== null) return cleanup();
    chromeProc.once("exit", cleanup);
    chromeProc.kill();
  });
}

// launchChrome starts headless Chrome and resolves to its DevTools URL.
function launchChrome() {
  chromeDir = mkdtempSync(join(tmpdir(), "tabs-e2e-chrome-"));
  chromeProc = spawn(CHROME, [
    "--headless=new",
    "--remote-debugging-port=0",
    `--user-data-dir=${chromeDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--no-sandbox", // CI runners and containers
    "--disable-gpu",
    "--host-resolver-rules=MAP *.localhost 127.0.0.1",
    "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  return new Promise((resolve, reject) => {
    let log = "";
    const timer = setTimeout(() => reject(new Error(`Chrome didn't start:\n${log}`)), 30000);
    chromeProc.stderr.on("data", (d) => {
      log += d;
      const m = log.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) { clearTimeout(timer); resolve(m[1]); }
    });
    chromeProc.on("exit", (code) => { clearTimeout(timer); reject(new Error(`Chrome exited (${code}):\n${log}`)); });
    chromeProc.on("error", (err) => { clearTimeout(timer); reject(new Error(`can't start Chrome (${CHROME}): ${err.message}`)); });
  });
}

// A minimal DevTools protocol client over one browser-level connection,
// with flattened sessions for each page.
class CDP {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.nextID = 0;
    this.pending = new Map();
    this.listeners = new Set();
    this.ready = new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
    });
    // If Chrome goes away, fail every call in flight rather than hang.
    this.ws.onclose = () => {
      for (const { reject } of this.pending.values()) reject(new Error("DevTools connection closed"));
      this.pending.clear();
    };
    this.ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
        return;
      }
      for (const l of this.listeners) l(msg);
    };
  }

  send(method, params = {}, sessionId, timeoutMs = 20000) {
    const id = ++this.nextID;
    this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timed out waiting for ${method}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
    });
  }

  // once resolves on the next event named method for sessionId.
  once(method, sessionId, timeoutMs = 20000) {
    return new Promise((resolve, reject) => {
      const done = () => { clearTimeout(timer); this.listeners.delete(listener); };
      const timer = setTimeout(() => { done(); reject(new Error(`timed out waiting for ${method}`)); }, timeoutMs);
      const listener = (msg) => {
        if (msg.method === method && msg.sessionId === sessionId) { done(); resolve(msg.params); }
      };
      this.listeners.add(listener);
    });
  }
}

// Page is one tab in its own browser context (its own cookie jar), so
// each person in the test is a separate "browser".
class Page {
  static async open(cdp) {
    const { browserContextId } = await cdp.send("Target.createBrowserContext");
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank", browserContextId });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    await cdp.send("Page.enable", {}, sessionId);
    return new Page(cdp, sessionId);
  }

  constructor(cdp, sessionId) {
    this.cdp = cdp;
    this.sessionId = sessionId;
  }

  // eval runs test code in the page under test (DevTools Runtime.evaluate).
  // Only this script's own expressions reach it; form values are embedded
  // with JSON.stringify.
  async eval(expression) {
    const r = await this.cdp.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, this.sessionId);
    if (r.exceptionDetails) throw new Error(`in page: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
    return r.result.value;
  }

  // state is where the page ended up. The URL drops the #fragment: the
  // sidebar's script adds #<tab> once it opens a tab.
  state() {
    return this.eval("({ url: location.href.split('#')[0], text: document.body.innerText, html: document.documentElement.outerHTML })");
  }

  async goto(url) {
    const loaded = this.cdp.once("Page.loadEventFired", this.sessionId);
    await this.cdp.send("Page.navigate", { url }, this.sessionId);
    await loaded;
    return this.state();
  }

  // submit fills the form matching selector and clicks its submit button,
  // as a person would, then waits for the resulting page. Checkbox fields
  // are given as the value to tick.
  async submit(selector, fields = {}) {
    const loaded = this.cdp.once("Page.loadEventFired", this.sessionId);
    await this.eval(`(() => {
      const form = document.querySelector(${JSON.stringify(selector)});
      if (!form) throw new Error("no form matches " + ${JSON.stringify(selector)} + " on " + location.href);
      for (const [name, value] of Object.entries(${JSON.stringify(fields)})) {
        const boxes = form.querySelectorAll('input[type=checkbox][name="' + name + '"]');
        if (boxes.length) {
          const box = [...boxes].find((b) => b.value === value);
          if (!box) throw new Error("no checkbox " + name + "=" + value);
          box.checked = true;
          continue;
        }
        const el = form.querySelector('[name="' + name + '"]');
        if (!el) throw new Error("no field " + name);
        el.value = value;
      }
      form.querySelector("button[type=submit], button:not([type])").click();
    })()`);
    await loaded;
    return this.state();
  }
}

let cdp;
// If the Go test runs out of time it sends SIGTERM: don't leave Chrome behind.
process.on("SIGTERM", async () => {
  await stopChrome();
  process.exit(1);
});
let failed = false;
try {
  cdp = new CDP(await launchChrome());
  await cdp.ready;

  // 1. The first admin, from the setup link.
  const admin = await Page.open(cdp);
  let st = await admin.goto(SETUP);
  assert.equal(st.url, `${AUTH}/_tabs/setup`, "the setup token is moved out of the URL");
  assert.match(st.text, /Create the first admin/);
  st = await admin.submit('form[action="/_tabs/setup"]', { username: "root", name: "Root", password: ADMIN_PW, confirm: ADMIN_PW });
  assert.match(st.text, /Your admin account is ready/, `setup failed: ${st.text}`);

  // 2. Log in through the portal: the handoff goes to the auth host and back.
  st = await admin.goto(`${PORTAL}/`);
  assert.ok(st.url.startsWith(`${AUTH}/_tabs/login`), `portal should send you to log in, got ${st.url}`);
  st = await admin.submit('form[action="/_tabs/login"]', { username: "root", password: ADMIN_PW });
  assert.equal(st.url, `${PORTAL}/`, `login should land on the sidebar: ${st.text}`);

  // 3. Create the group the tab needs, and an invite into it.
  await admin.goto(`${AUTH}/_tabs/admin/groups`);
  st = await admin.submit("form:has(input[name=action][value=create])", { name: "users" });
  assert.match(st.text, /Saved\./, `creating the group failed: ${st.text}`);
  await admin.goto(`${AUTH}/_tabs/admin/invites`);
  st = await admin.submit("form:has(input[name=action][value=create])", { groups: "users", hours: "24", uses: "1", note: "Welcome to tabs" });
  const link = st.html.match(/http:\/\/auth\.localhost:\d+\/_tabs\/invite\/[A-Za-z0-9_-]+/)?.[0];
  assert.ok(link, `no invite link shown: ${st.text}`);

  // 4. The invitee, in a browser of their own, signs up from the link.
  const guest = await Page.open(cdp);
  st = await guest.goto(link);
  assert.equal(st.url, `${AUTH}/_tabs/invite`, "the invite token is moved out of the URL");
  assert.match(st.text, /Welcome to tabs/);
  st = await guest.submit('form[action="/_tabs/invite"]', { username: "newbie", name: "New Person", password: GUEST_PW, confirm: GUEST_PW });
  assert.equal(st.url, `${PORTAL}/`, `signing up should land on the sidebar: ${st.text}`);
  assert.match(st.html, /data-slug="app"/, "the invite's group shows its tab");
  assert.match(st.text, /New Person/);

  // 5. The invite worked once.
  const late = await Page.open(cdp);
  st = await late.goto(link);
  assert.match(st.text, /Invite not valid/, "a used invite is refused");

  // 6. The new user logs out from the sidebar, and is logged out.
  st = await guest.submit("form.logout-form");
  assert.equal(st.url, `${AUTH}/_tabs/logged-out`, `logout: ${st.text}`);
  st = await guest.goto(`${PORTAL}/`);
  assert.ok(st.url.startsWith(`${AUTH}/_tabs/login`), "after logout the portal asks you to log in");

  // 7. And can log back in with the password they chose.
  st = await guest.submit('form[action="/_tabs/login"]', { username: "newbie", password: GUEST_PW });
  assert.equal(st.url, `${PORTAL}/`, `logging back in: ${st.text}`);

  console.log("ok: signup flow passed in a real browser");
} catch (err) {
  failed = true;
  console.error(err);
} finally {
  cdp?.ws.close();
  await stopChrome();
}
process.exit(failed ? 1 : 0);
