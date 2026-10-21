const button = document.getElementById('copyBtn');
if (button) {
  const prompt = document.getElementById('promptText');
  const status = document.getElementById('copyStatus');
  button.addEventListener('click', async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(prompt.textContent.trim());
      button.textContent = 'Copy again';
      status.textContent = 'Copied. Paste it into your agent’s chat.';
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(prompt);
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = 'Try copying again';
      status.textContent = 'Clipboard unavailable. Copy the selected text manually.';
    }
  });
}

const navToggle = document.querySelector('.nav-toggle');
const mainNav = document.getElementById('main-nav');
if (navToggle && mainNav) {
  const setNavOpen = (open) => {
    mainNav.classList.toggle('open', open);
    navToggle.setAttribute('aria-expanded', String(open));
  };
  navToggle.addEventListener('click', () => {
    setNavOpen(navToggle.getAttribute('aria-expanded') !== 'true');
  });
  mainNav.addEventListener('click', (event) => {
    if (event.target.closest('a')) setNavOpen(false);
  });
}
