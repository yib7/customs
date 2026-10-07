// Applies the saved theme before first paint to avoid a flash. External file so the page
// works under a strict Content-Security-Policy without inline scripts.
(function () {
  try {
    var t = window.localStorage.getItem('customs-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    // Storage unavailable: follow the system theme.
  }
})();
