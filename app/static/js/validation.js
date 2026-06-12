document.addEventListener('DOMContentLoaded', () => {
  const lines = document.querySelectorAll('[data-replay-step]');
  lines.forEach((line, index) => {
    line.style.transitionDelay = `${Math.min(index * 80, 800)}ms`;
    line.classList.add('replay-visible');
  });
});
