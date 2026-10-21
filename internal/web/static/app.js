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

  window.addEventListener("hashchange", function () { select(fromHash()); });

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

  if (tabs.length > 0 && !select(fromHash())) {
    history.replaceState(null, "", "#" + tabs[0].slug);
    select(tabs[0].slug);
  }
})();
