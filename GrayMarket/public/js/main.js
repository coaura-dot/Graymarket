// Gray Market — main.js v3

// Fechar menu mobile ao clicar num link
document.addEventListener('DOMContentLoaded', function () {
  var toggle = document.getElementById('menu-toggle');
  if (toggle) {
    document.querySelectorAll('nav a').forEach(function (a) {
      a.addEventListener('click', function () { toggle.checked = false; });
    });
  }

  // Copiar chave PIX
  var btnCopy = document.getElementById('btn-copiar-pix');
  if (btnCopy) {
    btnCopy.addEventListener('click', function () {
      var chave = document.getElementById('chave-pix');
      if (chave) {
        navigator.clipboard.writeText(chave.textContent.trim()).then(function () {
          btnCopy.textContent = 'Copiado!';
          setTimeout(function () { btnCopy.textContent = 'Copiar chave'; }, 2000);
        });
      }
    });
  }
});
