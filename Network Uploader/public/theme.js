// public/theme.js
function toggleTheme() {
  const body = document.body;
  const newTheme = body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  
  // Update onmiddellijk
  body.setAttribute('data-theme', newTheme);
  
  // Forceer herladen van CSS (zonder pagina refresh)
  const stylesheets = document.querySelectorAll('link[rel="stylesheet"]');
  stylesheets.forEach(sheet => {
      sheet.href = sheet.href.split('?')[0] + '?t=' + new Date().getTime();
  });
  
  localStorage.setItem('theme', newTheme);
}

// Initialisatie
document.addEventListener('DOMContentLoaded', () => {
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.body.setAttribute('data-theme', savedTheme);
});