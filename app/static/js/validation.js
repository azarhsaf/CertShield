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
  const result = host.querySelector('[data-walkthrough-result]');
  const validationId = host.dataset.validationId;
  const csrfToken = host.dataset.csrfToken;
  let index = 0;

  const safeText = (value) => String(value || '').replace(/[^A-Za-z0-9_.@-]/g, '').slice(0, 100);

  const appendLine = (item, echoValue) => {
    const row = document.createElement('div');
    row.className = `terminal-line guided-line guided-${item.type || 'line'}`;
    const speaker = document.createElement('span');
    speaker.className = 'terminal-speaker';
    speaker.textContent = `${item.speaker || 'CertShield'}>`;
    const text = document.createElement('span');
    text.className = 'terminal-message-inline';
    text.textContent = echoValue ? `${item.text} ${echoValue}` : item.text;
    row.append(speaker, text);
    lines.appendChild(row);
    requestAnimationFrame(() => row.classList.add('replay-visible'));
    lines.scrollTop = lines.scrollHeight;
  };

  const clearControls = () => {
    controls.replaceChildren();
  };

  const finish = () => {
    clearControls();
    result.hidden = false;
    result.classList.add('replay-visible');
  };

  const advance = () => {
    clearControls();
    if (index >= script.length) {
      finish();
      return;
    }
    const item = script[index];
    index += 1;
    appendLine(item);

    if (item.type === 'continue') {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'terminal-action';
      button.textContent = 'Press Enter to continue';
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
      input.maxLength = 100;
      input.autocomplete = 'off';
      input.placeholder = item.placeholder || 'Type demo value only — not executed';
      const button = document.createElement('button');
      button.type = 'submit';
      button.className = 'terminal-action';
      button.textContent = 'Record demo note';
      form.append(input, button);
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const sanitized = safeText(input.value);
        if (!sanitized) {
          appendLine({ speaker: 'Walkthrough', type: 'line', text: 'Input rejected. Use a harmless non-secret label with safe characters only.' });
          input.value = '';
          input.focus();
          return;
        }
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
            appendLine({ speaker: 'Walkthrough', type: 'line', text: 'Input rejected by safety filter. Continue with a harmless label only.' });
            return;
          }
        } catch (error) {
          appendLine({ speaker: 'Walkthrough', type: 'line', text: 'Demo note stayed in this browser session. The walkthrough remains non-executing.' });
        }
        appendLine({ speaker: 'Input required', type: 'line', text: 'Demo value accepted as note only:' }, sanitized);
        advance();
      });
      controls.appendChild(form);
      input.focus();
      return;
    }

    if (item.type === 'choice') {
      const choices = item.options || ['Continue'];
      choices.forEach((choice) => {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'terminal-choice';
        button.textContent = choice;
        button.addEventListener('click', () => {
          appendLine({ speaker: 'Walkthrough', type: 'line', text: 'Safe review selection recorded:' }, choice);
          advance();
        });
        controls.appendChild(button);
      });
      return;
    }

    window.setTimeout(advance, 450);
  };

  host.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && controls.querySelector('.terminal-action')) {
      const activeTag = document.activeElement ? document.activeElement.tagName : '';
      if (activeTag !== 'INPUT') {
        event.preventDefault();
        controls.querySelector('.terminal-action').click();
      }
    }
  });

  advance();
});
