document.addEventListener('DOMContentLoaded', () => {
  const host = document.querySelector('[data-validation-walkthrough]');
  const dataNode = document.getElementById('validation-run-data');
  if (!host || !dataNode) {
    document.querySelectorAll('[data-replay-step]').forEach((line, index) => {
      line.style.transitionDelay = `${Math.min(index * 80, 800)}ms`;
      line.classList.add('replay-visible');
    });
    return;
  }

  const run = JSON.parse(dataNode.textContent || '{}');
  const script = (run.evidence && run.evidence.walkthrough_script) || [];
  const lines = host.querySelector('[data-walkthrough-lines]');
  const controls = host.querySelector('[data-walkthrough-controls]');
  const restart = document.querySelector('[data-console-restart]');
  const validationId = host.dataset.validationId;
  const csrfToken = host.dataset.csrfToken;
  const inputValues = {};
  let index = 0;
  let typing = false;

  const cleanDisplayText = (value) => String(value || '')
    .replace(/<[^>]*>/g, '')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .slice(0, 80);

  const withInputs = (text) => String(text || '').replace(/\{\{([A-Za-z0-9_.@-]+)\}\}/g, (_match, name) => inputValues[name] || '[not provided]');

  const promptFor = (item) => {
    if (item.type === 'simulated') return '';
    return `${(item.speaker || 'certshield').toLowerCase()}>`;
  };

  const typeInto = (node, value, done) => {
    const text = withInputs(value);
    let offset = 0;
    typing = true;
    const tick = () => {
      node.textContent = text.slice(0, offset);
      offset += 1;
      lines.scrollTop = lines.scrollHeight;
      if (offset <= text.length) {
        window.setTimeout(tick, Math.min(24, 8 + text.length));
        return;
      }
      typing = false;
      done();
    };
    tick();
  };

  const appendLine = (item, done = () => {}) => {
    const row = document.createElement('div');
    row.className = `console-line console-${item.type || 'line'}`;
    const prompt = document.createElement('span');
    prompt.className = 'console-prompt';
    prompt.textContent = promptFor(item);
    const text = document.createElement('span');
    text.className = 'console-text';
    row.append(prompt, text);
    lines.appendChild(row);
    requestAnimationFrame(() => row.classList.add('replay-visible'));
    typeInto(text, item.text, done);
  };

  const clearControls = () => controls.replaceChildren();

  const finish = () => {
    clearControls();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'terminal-action';
    button.textContent = 'Restart simulation';
    button.addEventListener('click', reset);
    controls.appendChild(button);
  };

  const advance = () => {
    if (typing) return;
    clearControls();
    if (index >= script.length) {
      finish();
      return;
    }
    const item = script[index];
    index += 1;
    appendLine(item, () => showControl(item));
  };

  const submitInput = async (item, rawValue) => {
    const sanitized = cleanDisplayText(rawValue).trim();
    if (!sanitized) {
      appendLine({ speaker: 'operator', type: 'line', text: 'Input was empty after sanitization. Type a demo label only.' });
      return;
    }
    inputValues[item.name || 'walkthrough_note'] = sanitized;
    const body = new URLSearchParams();
    body.set('csrf_token', csrfToken);
    body.set('name', item.name || 'walkthrough_note');
    body.set('value', sanitized);
    try {
      const response = await fetch(`/api/v1/validations/${validationId}/walkthrough-input`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      if (!response.ok) {
        appendLine({ speaker: 'operator', type: 'line', text: 'Input was rejected because it looked like a secret. Use a demo label only.' });
        return;
      }
    } catch (error) {
      appendLine({ speaker: 'operator', type: 'line', text: 'Input stayed in browser memory. Simulation can continue without execution.' });
    }
    appendLine({ speaker: 'input', type: 'line', text: sanitized }, advance);
  };

  const showControl = (item) => {
    if (item.type === 'continue') {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'terminal-action';
      button.textContent = 'Press Enter';
      button.addEventListener('click', advance);
      controls.appendChild(button);
      button.focus();
      return;
    }

    if (item.type === 'input') {
      const form = document.createElement('form');
      form.className = 'terminal-input-form';
      const input = document.createElement('input');
      input.type = 'text';
      input.name = 'value';
      input.maxLength = 80;
      input.autocomplete = 'off';
      input.placeholder = 'Type demo value only — not executed';
      const button = document.createElement('button');
      button.type = 'submit';
      button.className = 'terminal-action';
      button.textContent = 'Enter';
      form.append(input, button);
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        clearControls();
        submitInput(item, input.value);
      });
      controls.appendChild(form);
      input.focus();
      return;
    }

    window.setTimeout(advance, item.type === 'simulated' ? 650 : 350);
  };

  function reset() {
    index = 0;
    typing = false;
    Object.keys(inputValues).forEach((key) => delete inputValues[key]);
    lines.replaceChildren();
    clearControls();
    advance();
  }

  host.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && controls.querySelector('.terminal-action')) {
      const activeTag = document.activeElement ? document.activeElement.tagName : '';
      if (activeTag !== 'INPUT') {
        event.preventDefault();
        controls.querySelector('.terminal-action').click();
      }
    }
  });

  if (restart) restart.addEventListener('click', reset);
  reset();
});
