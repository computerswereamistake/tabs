// Tabs: sidebar of apps, each shown in a lazily created, kept-alive iframe.
(function () {
  "use strict";

  var tabs = JSON.parse(document.getElementById("tabs-data").textContent) || [];
  // Maps, not plain objects: the hash is user input, and "#constructor" or
  // "#__proto__" must not match Object.prototype members.
  var bySlug = new Map();
  tabs.forEach(function (t) { bySlug.set(t.slug, t); });

  var shell = document.getElementById("shell");
  var frames = document.getElementById("frames");
  var activeName = document.getElementById("active-name");
  var reloadBtn = document.getElementById("reload");
  var popout = document.getElementById("popout");
  var toggle = document.getElementById("toggle");
  var toggleMobile = document.getElementById("toggle-mobile");
  var scrim = document.getElementById("scrim");
  var links = document.querySelectorAll(".tab[data-slug]");
  var mobile = window.matchMedia("(max-width: 767px)");

  var iframes = new Map(); // slug -> iframe, created on first selection
  var active = null;

  function setCollapsed(collapsed) {
    shell.classList.toggle("collapsed", collapsed);
    toggle.setAttribute("aria-expanded", String(!collapsed));
    toggleMobile.setAttribute("aria-expanded", String(!collapsed));
    scrim.hidden = collapsed || !mobile.matches;
  }

  function select(slug) {
    var t = bySlug.get(slug);
    if (!t) return false;
    var frame = iframes.get(slug);
    if (!frame) {
      frame = document.createElement("iframe");
      frame.src = t.url;
      frame.title = t.name;
      frame.setAttribute("allow", "fullscreen");
      frame.setAttribute("referrerpolicy", "same-origin");
      // A navigation inside the app is a good moment to check the session:
      // if it expired, that navigation was just sent to the login page,
      // which refuses to be framed.
      frame.addEventListener("load", function () { checkSession(false); });
      iframes.set(slug, frame);
      frames.appendChild(frame);
    }
    iframes.forEach(function (f, s) { f.hidden = s !== slug; });
    links.forEach(function (a) {
      var on = a.getAttribute("data-slug") === slug;
      a.classList.toggle("active", on);
      if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    });
    active = slug;
    activeName.textContent = t.name;
    document.title = t.name + " · " + document.querySelector(".brand-title").textContent;
    popout.href = t.url;
    reloadBtn.hidden = false;
    popout.hidden = false;
    if (mobile.matches) setCollapsed(true);
    return true;
  }

  function fromHash() {
    try {
      return decodeURIComponent(location.hash.replace(/^#/, ""));
    } catch (e) {
      return "";
    }
  }

  window.addEventListener("hashchange", function () {
    if (select(fromHash())) checkSession(false);
  });

  // Session watch. Framed apps can't show the login page (it refuses to be
  // framed), so an expired session would otherwise leave a blank frame. We
  // check at natural moments rather than on a timer: a timer would keep the
  // auth session alive forever and defeat its inactivity timeout.
  var RETURN_KEY = "tabs:return";     // tab to reopen after logging in
  var RELOADED_KEY = "tabs:reloaded"; // set when we reload for login
  var banner = document.getElementById("session-banner");
  var lastCheck = 0;
  var checking = false;

  // sessionStorage can throw (privacy modes); it's only a convenience.
  function store(k, v) {
    try {
      if (v === null) sessionStorage.removeItem(k); else sessionStorage.setItem(k, v);
    } catch (e) { /* ignore */ }
  }
  function load(k) {
    try { return sessionStorage.getItem(k); } catch (e) { return null; }
  }

  function sessionExpired() {
    if (active) store(RETURN_KEY, active);
    // If we already reloaded for login and the check still fails, the page
    // itself loaded fine, so something else is wrong (e.g. the check route
    // isn't behind forward-auth). Show a banner instead of looping.
    if (load(RELOADED_KEY)) {
      banner.hidden = false;
      return;
    }
    store(RELOADED_KEY, "1");
    location.reload();
  }

  function checkSession(force) {
    var now = Date.now();
    if (checking || (!force && now - lastCheck < 15000)) return;
    checking = true;
    lastCheck = now;
    fetch("/_tabs/session", { credentials: "same-origin", redirect: "manual", cache: "no-store" })
      .then(function (r) {
        if (r.ok) {
          store(RELOADED_KEY, null);
          banner.hidden = true;
        } else if (r.type === "opaqueredirect" || r.status === 401 || r.status === 403) {
          sessionExpired();
        }
        // Anything else (5xx, 404) says nothing about the session.
      })
      .catch(function () { /* offline: say nothing */ })
      .then(function () { checking = false; });
  }

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") checkSession(false);
  });
  window.addEventListener("focus", function () { checkSession(false); });
  document.getElementById("session-login").addEventListener("click", function () {
    if (active) store(RETURN_KEY, active);
    store(RELOADED_KEY, null);
  });

  reloadBtn.addEventListener("click", function () {
    var frame = iframes.get(active);
    if (!frame) return;
    try {
      frame.contentWindow.location.reload();
    } catch (e) {
      // Cross-origin: we cannot reach into the frame, so reset its src.
      frame.src = bySlug.get(active).url;
    }
  });

  // Open the frame's current page when we can read it (same-origin).
  popout.addEventListener("click", function () {
    var frame = iframes.get(active);
    if (!frame) return;
    try {
      var href = frame.contentWindow.location.href;
      if (href && href !== "about:blank") popout.href = href;
    } catch (e) {
      popout.href = bySlug.get(active).url;
    }
  });

  toggle.addEventListener("click", function () {
    setCollapsed(!shell.classList.contains("collapsed"));
  });
  toggleMobile.addEventListener("click", function () { setCollapsed(false); });
  scrim.addEventListener("click", function () { setCollapsed(true); });
  mobile.addEventListener("change", function (e) { setCollapsed(e.matches); });

  // A missing icon file falls back to the tab's initial.
  function iconFallback(img) {
    var letter = document.createElement("span");
    letter.className = "tab-icon tab-icon-letter";
    letter.setAttribute("aria-hidden", "true");
    var name = img.parentNode.querySelector(".tab-name");
    letter.textContent = name ? Array.from(name.textContent.trim())[0] || "" : "";
    img.replaceWith(letter);
  }
  document.querySelectorAll("img.tab-icon").forEach(function (img) {
    // decode() rejects for images that failed, even if they failed before
    // this deferred script ran. naturalWidth is unreliable for unsized SVGs.
    img.decode().catch(function () { iconFallback(img); });
  });

  setCollapsed(mobile.matches);

  // The login redirect drops the #hash, so fall back to the tab we stored
  // before sending the page through login.
  var returnTo = load(RETURN_KEY);
  store(RETURN_KEY, null);
  var initial = [fromHash(), returnTo, tabs.length ? tabs[0].slug : ""].find(function (s) {
    return bySlug.has(s);
  });
  if (initial) {
    if (fromHash() !== initial) history.replaceState(null, "", "#" + initial);
    select(initial);
  }
  checkSession(true);
})();
