document.addEventListener('DOMContentLoaded', () => {
  const host = document.getElementById('exposure-console-terminal') || document.querySelector('[data-validation-walkthrough]');
  const dataNode = document.getElementById('validation-run-data');
  if (!host || !dataNode) {
    document.querySelectorAll('[data-replay-step]').forEach((line, index) => {
      line.style.transitionDelay = `${Math.min(index * 80, 800)}ms`;
      line.classList.add('replay-visible');
    });
    return;
  }

  const lines = host.querySelector('[data-walkthrough-lines]') || host;
  const controls = host.querySelector('[data-walkthrough-controls]') || document.createElement('div');
  const restart = document.querySelector('[data-console-restart]');
  const validationId = host.dataset.validationId;
  const csrfToken = host.dataset.csrfToken;
  const inputValues = {};
  let run = {};
  let script = [];
  let index = 0;
  let typing = false;

  const cleanDisplayText = (value) => String(value || '')
    .replace(/<[^>]*>/g, '')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .slice(0, 80);

  const errorLine = (message) => ({ speaker: 'certshield', type: 'line', text: message });

  const fallbackScript = (sourceRun) => {
    const evidence = sourceRun.evidence || {};
    const nested = evidence.evidence_json || {};
    const result = sourceRun.result_label || sourceRun.result || 'Evidence Incomplete';
    const target = sourceRun.target || nested.template_name || nested.name || 'collected finding';
    const title = evidence.simulation_summary || sourceRun.summary || 'Finding loaded from validation history';
    return [
      { speaker: 'certshield', type: 'line', text: 'finding loaded' },
      { speaker: 'certshield', type: 'line', text: `target: ${target}` },
      { speaker: 'certshield', type: 'line', text: `evidence summary: ${title}` },
      { speaker: 'input', type: 'input', name: 'demo_identity', text: 'type demo identity label:' },
      { speaker: '', type: 'simulated', text: '[SIMULATED] build request preview using collected evidence' },
      { speaker: '', type: 'simulated', text: '[SIMULATED] identity label: {{demo_identity}}' },
      { speaker: 'certshield', type: 'line', text: 'no certificate was requested' },
      { speaker: 'certshield', type: 'line', text: 'no authentication was attempted' },
      { speaker: 'certshield', type: 'banner', text: `RESULT: ${String(result).toUpperCase()}` },
    ];
  };

  const loadScript = () => {
    try {
      run = JSON.parse(dataNode.textContent || '{}');
    } catch (error) {
      run = {};
      script = [
        errorLine('console error: validation-run-data could not be parsed'),
        errorLine('fallback simulation started without executing anything'),
        ...fallbackScript({ result_label: 'Evidence Incomplete' }),
      ];
      return;
    }
    const supplied = run.evidence && Array.isArray(run.evidence.walkthrough_script) ? run.evidence.walkthrough_script : [];
    script = supplied.length >= 5 ? supplied : fallbackScript(run);
  };

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
        window.setTimeout(tick, Math.min(22, 7 + Math.floor(text.length / 12)));
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

  const clearControls = () => {
    controls.hidden = true;
    controls.replaceChildren();
  };

  const showControls = () => {
    controls.hidden = false;
  };

  const finish = () => {
    clearControls();
    showControls();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'terminal-action';
    button.textContent = 'Restart simulation';
    button.addEventListener('click', startTerminal);
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
      appendLine({ speaker: 'operator', type: 'line', text: 'input was empty after sanitization; type a demo label only' }, () => showControl(item));
      return;
    }
    inputValues[item.name || 'walkthrough_note'] = sanitized;
    const body = new URLSearchParams();
    body.set('csrf_token', csrfToken || '');
    body.set('name', item.name || 'walkthrough_note');
    body.set('value', sanitized);
    try {
      const response = await fetch(`/api/v1/validations/${validationId}/walkthrough-input`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
      if (!response.ok) {
        appendLine({ speaker: 'operator', type: 'line', text: 'input was rejected because it looked like a secret; use a demo label only' }, () => showControl(item));
        return;
      }
    } catch (error) {
      appendLine({ speaker: 'operator', type: 'line', text: 'input stayed in browser memory; simulation continues without execution' });
    }
    appendLine({ speaker: 'input', type: 'line', text: sanitized }, advance);
  };

  const showControl = (item) => {
    if (item.type === 'continue') {
      showControls();
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
      showControls();
      const form = document.createElement('form');
      form.className = 'terminal-input-form';
      const prompt = document.createElement('span');
      prompt.className = 'console-prompt';
      prompt.textContent = `${(item.speaker || 'input').toLowerCase()}>`;
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
      form.append(prompt, input, button);
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        clearControls();
        submitInput(item, input.value);
      });
      controls.appendChild(form);
      input.focus();
      return;
    }

    window.setTimeout(advance, item.type === 'simulated' ? 520 : 240);
  };

  function startTerminal() {
    loadScript();
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

  if (restart) restart.addEventListener('click', startTerminal);
  startTerminal();
});
