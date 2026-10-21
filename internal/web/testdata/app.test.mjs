// Tests for static/app.js, run with Node's built-in runner (no dependencies):
//
//	node --test internal/web/testdata/
//
// app.js runs in a vm context against a minimal fake DOM that models only
// what the script touches. This file lives outside static/ so it is never
// embedded or served.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const source = readFileSync(new URL("../static/app.js", import.meta.url), "utf8");

class El {
  constructor(tag, attrs = {}) {
    this.tagName = tag;
    this.attrs = { ...attrs };
    this.hidden = false;
    this.textContent = "";
    this.listeners = {};
    this.children = [];
    this.parentNode = null;
    const classes = new Set();
    this.classList = {
      toggle: (c, on) => { if (on ?? !classes.has(c)) classes.add(c); else classes.delete(c); },
      contains: (c) => classes.has(c),
    };
  }
  set className(v) { v.split(/\s+/).forEach((c) => this.classList.toggle(c, true)); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatch(type, ev = {}) { (this.listeners[type] || []).forEach((fn) => fn(ev)); }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
}

const TABS = [
  { slug: "alpha", name: "Alpha", url: "/alpha/" },
  { slug: "beta", name: "Beta", url: "https://beta.example.com/" },
  { slug: "gamma", name: "Gamma", url: "/gamma/" },
];

// boot runs app.js in a fresh fake browser and returns handles for tests.
// responses: what successive fetches of /_tabs/session return; each entry is
// a status number, "redirect", or "reject". The last entry repeats.
function boot({ hash = "", storage = {}, storageBroken = false, responses = [204] } = {}) {
  const clock = { now: 0 };
  const byId = {};
  const add = (id, el = new El("div")) => (byId[id] = el);
  add("tabs-data").textContent = JSON.stringify(TABS);
  ["shell", "frames", "active-name", "reload", "popout", "toggle", "toggle-mobile", "scrim", "session-login"].forEach((id) => add(id));
  add("session-banner").hidden = true;
  const brand = new El("span");
  brand.textContent = "Media";
  const links = TABS.map((t) => new El("a", { "data-slug": t.slug }));

  const created = [];
  const docListeners = {};
  const document = {
    title: "",
    visibilityState: "visible",
    getElementById: (id) => byId[id] || null,
    querySelector: (sel) => (sel === ".brand-title" ? brand : null),
    querySelectorAll: (sel) => (sel === ".tab[data-slug]" ? links : []),
    createElement: (tag) => {
      const el = new El(tag);
      el.contentDocument = null; // cross-origin unless a test says otherwise
      created.push(el);
      return el;
    },
    addEventListener: (type, fn) => (docListeners[type] ||= []).push(fn),
  };

  const store = new Map(Object.entries(storage));
  const sessionStorage = {
    getItem: (k) => { if (storageBroken) throw new Error("denied"); return store.has(k) ? store.get(k) : null; },
    setItem: (k, v) => { if (storageBroken) throw new Error("denied"); store.set(k, String(v)); },
    removeItem: (k) => { if (storageBroken) throw new Error("denied"); store.delete(k); },
  };

  const fetches = [];
  const queue = [...responses];
  const fetch = (url, opts) => {
    fetches.push({ url, opts });
    const r = queue.length > 1 ? queue.shift() : queue[0];
    if (r === "reject") return Promise.reject(new TypeError("offline"));
    if (r === "redirect") return Promise.resolve({ ok: false, status: 0, type: "opaqueredirect" });
    return Promise.resolve({ ok: r >= 200 && r < 300, status: r, type: "basic" });
  };

  let reloads = 0;
  const location = { hash, reload: () => { reloads++; } };
  const winListeners = {};
  const window = {
    document,
    location,
    history: { replaceState: (_s, _t, url) => { location.hash = url; } },
    sessionStorage,
    fetch,
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    addEventListener: (type, fn) => (winListeners[type] ||= []).push(fn),
    // The confirm delay runs at once; tests control time via clock instead.
    setTimeout: (fn) => { Promise.resolve().then(fn); return 0; },
    Date: { now: () => clock.now },
  };
  window.window = window;
  vm.runInNewContext(source, window);

  const fire = (listeners, type, ev = {}) => (listeners[type] || []).forEach((fn) => fn(ev));
  return {
    clock, store, fetches, created, links,
    banner: byId["session-banner"],
    reloads: () => reloads,
    hash: () => location.hash,
    active: () => links.find((a) => a.classList.contains("active"))?.getAttribute("data-slug"),
    frameFor: (slug) => created.find((f) => f.src === TABS.find((t) => t.slug === slug).url),
    navigate(h) { location.hash = h; fire(winListeners, "hashchange"); },
    window: (type, ev) => fire(winListeners, type, ev),
    doc: (type, ev) => fire(docListeners, type, ev),
    clickLogin: () => byId["session-login"].dispatch("click"),
    setVisibility: (v) => { document.visibilityState = v; },
  };
}

// settle lets pending promise chains (fetch, confirm delay) finish.
const settle = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };

test("opens the tab named in the hash", () => {
  const b = boot({ hash: "#beta" });
  assert.equal(b.active(), "beta");
  assert.equal(b.created.length, 1);
});

test("unknown or prototype-named hash falls back to the first tab", () => {
  for (const hash of ["", "#nope", "#constructor", "#__proto__", "#toString", "#%E0%A4%A"]) {
    const b = boot({ hash });
    assert.equal(b.active(), "alpha", `hash ${hash}`);
    assert.equal(b.hash(), "#alpha", `hash ${hash}`);
  }
});

test("reopens the stored tab after a login round-trip, then forgets it", () => {
  const b = boot({ storage: { "tabs:return": "gamma" } });
  assert.equal(b.active(), "gamma");
  assert.equal(b.hash(), "#gamma");
  assert.equal(b.store.has("tabs:return"), false);
});

test("an explicit hash wins over the stored tab; a bogus stored tab is ignored", () => {
  assert.equal(boot({ hash: "#beta", storage: { "tabs:return": "gamma" } }).active(), "beta");
  assert.equal(boot({ storage: { "tabs:return": "constructor" } }).active(), "alpha");
});

test("iframes are created lazily, once, and kept alive when hidden", () => {
  const b = boot({ hash: "#alpha" });
  b.navigate("#beta");
  b.navigate("#alpha");
  b.navigate("#beta");
  assert.equal(b.created.length, 2);
  assert.equal(b.frameFor("alpha").hidden, true);
  assert.equal(b.frameFor("beta").hidden, false);
  assert.equal(b.active(), "beta");
});

test("navigating to an unknown hash keeps the current tab", () => {
  const b = boot({ hash: "#beta" });
  b.navigate("#nope");
  assert.equal(b.active(), "beta");
});

test("startup check passes: no reload, banner hidden, reload marker cleared", async () => {
  const b = boot({ storage: { "tabs:reloaded": "1" } });
  await settle();
  assert.equal(b.fetches.length, 1);
  assert.equal(b.fetches[0].url, "/_tabs/session");
  assert.equal(b.fetches[0].opts.redirect, "manual");
  assert.equal(b.reloads(), 0);
  assert.equal(b.banner.hidden, true);
  assert.equal(b.store.has("tabs:reloaded"), false);
});

test("expiry confirmed twice reloads, remembering the tab", async () => {
  for (const resp of [401, "redirect"]) {
    const b = boot({ hash: "#gamma", responses: [resp] });
    await settle();
    assert.equal(b.fetches.length, 2, `${resp}: confirms before acting`);
    assert.equal(b.reloads(), 1, `${resp}: reloads`);
    assert.equal(b.store.get("tabs:reloaded"), "1");
    assert.equal(b.store.get("tabs:return"), "gamma");
  }
});

test("a single stray 401 does not reload", async () => {
  const b = boot({ responses: [401, 204] });
  await settle();
  assert.equal(b.fetches.length, 2);
  assert.equal(b.reloads(), 0);
});

test("403, 5xx, 404 and network errors say nothing about the session", async () => {
  for (const resp of [403, 500, 502, 404, "reject"]) {
    const b = boot({ responses: [resp] });
    await settle();
    assert.equal(b.fetches.length, 1, `${resp}: no confirm`);
    assert.equal(b.reloads(), 0, `${resp}: no reload`);
    assert.equal(b.banner.hidden, true, `${resp}: no banner`);
  }
});

test("still expired right after a reload for login: banner instead of a loop", async () => {
  const b = boot({ storage: { "tabs:reloaded": "1" }, responses: [401] });
  await settle();
  assert.equal(b.reloads(), 0);
  assert.equal(b.banner.hidden, false);
});

test("without storage it never auto-reloads, only shows the banner", async () => {
  const b = boot({ storageBroken: true, responses: [401] });
  await settle();
  assert.equal(b.reloads(), 0);
  assert.equal(b.banner.hidden, false);
  assert.equal(b.active(), "alpha");
});

test("checks are throttled to one per 15 seconds", async () => {
  const b = boot({ hash: "#alpha" });
  await settle();
  b.clock.now = 5000;
  b.navigate("#beta");
  b.window("focus");
  b.doc("visibilitychange");
  await settle();
  assert.equal(b.fetches.length, 1);
  b.clock.now = 16000;
  b.navigate("#gamma");
  await settle();
  assert.equal(b.fetches.length, 2);
});

test("returning to the browser tab checks; becoming hidden does not", async () => {
  const b = boot();
  await settle();
  b.clock.now = 20000;
  b.setVisibility("hidden");
  b.doc("visibilitychange");
  await settle();
  assert.equal(b.fetches.length, 1);
  b.setVisibility("visible");
  b.doc("visibilitychange");
  await settle();
  assert.equal(b.fetches.length, 2);
});

test("clicks and keys inside a same-origin frame trigger a check", async () => {
  const b = boot({ hash: "#alpha" });
  await settle();
  const frame = b.frameFor("alpha");
  const inner = new El("document");
  frame.contentDocument = inner;
  frame.dispatch("load"); // within the throttle window: attaches listeners only
  await settle();
  assert.equal(b.fetches.length, 1);
  b.clock.now = 20000;
  inner.dispatch("pointerdown");
  await settle();
  assert.equal(b.fetches.length, 2);
  b.clock.now = 40000;
  inner.dispatch("keydown");
  await settle();
  assert.equal(b.fetches.length, 3);
});

test("a cross-origin frame load still checks without touching its document", async () => {
  const b = boot({ hash: "#beta" });
  await settle();
  b.clock.now = 20000;
  b.frameFor("beta").dispatch("load"); // contentDocument is null
  await settle();
  assert.equal(b.fetches.length, 2);
});

test("back/forward cache restore forces a check; a normal pageshow does not", async () => {
  const b = boot();
  await settle();
  b.window("pageshow", { persisted: false });
  await settle();
  assert.equal(b.fetches.length, 1);
  b.window("pageshow", { persisted: true });
  await settle();
  assert.equal(b.fetches.length, 2);
});

test("the banner's login link remembers the tab and clears the loop marker", async () => {
  const b = boot({ hash: "#beta", storage: { "tabs:reloaded": "1" }, responses: [401] });
  await settle();
  b.clickLogin();
  assert.equal(b.store.get("tabs:return"), "beta");
  assert.equal(b.store.has("tabs:reloaded"), false);
});
