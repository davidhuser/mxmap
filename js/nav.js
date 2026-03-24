/* nav.js — auto-renders navigation with pill tabs + dropdown overflow menu */
(function () {
  var path = window.location.pathname;
  var primary = [
    { href: '/', label: 'Email Map', match: ['/', '/index.html'] },
    { href: '/tenant.html', label: 'Tenant Map' },
  ];
  var secondary = [
    { href: '/impressum.html', label: 'Impressum' },
    { href: '/datenschutz.html', label: 'Datenschutz' },
  ];

  var nav = document.getElementById('nav');
  if (!nav) return;

  function isActive(link) {
    return link.match
      ? link.match.indexOf(path) !== -1
      : path === link.href;
  }

  function makeLink(link, extraClass) {
    var a = document.createElement('a');
    a.href = link.href;
    a.className = 'header-link' + (extraClass ? ' ' + extraClass : '');
    a.textContent = link.label;
    if (isActive(link)) a.classList.add('active');
    return a;
  }

  /* inline primary links as pill tabs (hidden on mobile via CSS) */
  var inlineWrap = document.createElement('span');
  inlineWrap.className = 'nav-primary';
  primary.forEach(function (link) {
    inlineWrap.appendChild(makeLink(link));
  });
  nav.appendChild(inlineWrap);

  /* toggle button */
  var toggle = document.createElement('button');
  toggle.className = 'nav-menu-toggle';
  toggle.setAttribute('aria-label', 'More links');
  toggle.setAttribute('aria-expanded', 'false');
  toggle.textContent = '\u22EF';
  nav.appendChild(toggle);

  /* dropdown menu */
  var menu = document.createElement('div');
  menu.className = 'nav-menu';
  primary.forEach(function (link) {
    menu.appendChild(makeLink(link, 'nav-menu-mobile'));
  });
  secondary.forEach(function (link) {
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
