/* nav.js - auto-renders dropdown overflow menu */
(function () {
  var path = window.location.pathname;
  var links = [
    { href: '/impressum.html', label: 'Impressum' },
    { href: '/datenschutz.html', label: 'Datenschutz' },
  ];

  var nav = document.getElementById('nav');
  if (!nav) return;

  function makeLink(link) {
    var a = document.createElement('a');
    a.href = link.href;
    a.className = 'header-link';
    a.textContent = link.label;
    if (path === link.href) a.classList.add('active');
    return a;
  }

  /* toggle button */
  var toggle = document.createElement('button');
  toggle.className = 'nav-menu-toggle';
  toggle.setAttribute('aria-label', 'More links');
  toggle.setAttribute('aria-expanded', 'false');
  toggle.textContent = '⋯';
  nav.appendChild(toggle);

  /* dropdown menu */
  var menu = document.createElement('div');
  menu.className = 'nav-menu';
  links.forEach(function (link) {
    menu.appendChild(makeLink(link));
  });
  nav.appendChild(menu);

  /* toggle handler */
  toggle.addEventListener('click', function (e) {
    e.stopPropagation();
    var open = menu.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(open));
  });

  /* close on outside click */
  document.addEventListener('click', function (e) {
    if (!menu.contains(e.target) && e.target !== toggle) {
      menu.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
    }
  });
})();
