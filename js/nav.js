/* nav.js — auto-renders navigation links with active state detection */
(function () {
  var path = window.location.pathname;
  var links = [
    { href: '/', label: 'Email Map', match: ['/', '/index.html'] },
    { href: '/tenant.html', label: 'Tenant Map' },
    { href: '/impressum.html', label: 'Impressum' },
    { href: '/datenschutz.html', label: 'Datenschutz' },
  ];
  var nav = document.getElementById('nav');
  if (!nav) return;
  links.forEach(function (link) {
    var a = document.createElement('a');
    a.href = link.href;
    a.className = 'header-link';
    a.textContent = link.label;
    var isActive = link.match
      ? link.match.indexOf(path) !== -1
      : path === link.href;
    if (isActive) a.classList.add('active');
    nav.appendChild(a);
  });
})();
