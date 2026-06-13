document.addEventListener('DOMContentLoaded', () => {
  const host = document.getElementById('exposure-console-terminal') || document.querySelector('[data-validation-walkthrough]');
  const dataNode = document.getElementById('validation-run-data');
  if (!host || !dataNode) return;

  const lines = host.querySelector('[data-walkthrough-lines]') || host;
  const controls = host.querySelector('[data-walkthrough-controls]') || document.createElement('div');
  const restart = document.querySelector('[data-console-restart]');
  const allowedControls = new Set(['ANALYZE', 'REQUEST', 'AUTH', 'FIX', 'RESTART']);
  let run = {};
  let script = [];
  let index = 0;
  let typing = false;

  const cleanControlText = (value) => String(value || '')
    .replace(/<[^>]*>/g, '')
    .replace(/[\x00-\x1f\x7f]/g, '')
    .trim()
    .toUpperCase()
    .slice(0, 16);

  const fallbackScript = (sourceRun) => {
    const evidence = sourceRun.evidence || {};
    const result = sourceRun.result_label || sourceRun.result || 'Evidence Incomplete';
    const target = sourceRun.target || 'incomplete';
    return [
      { speaker: 'operator', type: 'command', text: 'operator@certshield:~$ certipy-ad find --replay-from-certshield-evidence' },
      { speaker: '', type: 'line', text: '[+] Domain loaded' },
      { speaker: '', type: 'line', text: `    Target                         : ${target}` },
      { speaker: '', type: 'line', text: `    Evidence summary               : ${evidence.simulation_summary || sourceRun.summary || 'incomplete'}` },
      { speaker: 'input', type: 'control', expected: 'ANALYZE', text: 'Type ANALYZE to inspect the collected finding evidence:' },
      { speaker: '', type: 'replay', text: '[REPLAY] Risk calculation evaluated from stored evidence only' },
      { speaker: 'input', type: 'control', expected: 'REQUEST', text: 'Type REQUEST to replay risk calculation:' },
      { speaker: '', type: 'replay', text: '[REPLAY] Request status  : not sent' },
      { speaker: '', type: 'replay', text: '[REPLAY] Certificate     : not created' },
      { speaker: 'input', type: 'control', expected: 'AUTH', text: 'Type AUTH to replay authentication impact:' },
      { speaker: '', type: 'replay', text: '[REPLAY] Authentication attempt : not performed' },
      { speaker: 'certshield', type: 'banner', text: `RESULT: ${String(result).toUpperCase()}` },
      { speaker: 'input', type: 'control', expected: 'FIX', text: 'Type FIX to view remediation:' },
      { speaker: 'certshield', type: 'final', text: 'Replay complete. No certificate was requested, no authentication was attempted, and no environment change was made.' },
    ];
  };

  const loadScript = () => {
    try {
      run = JSON.parse(dataNode.textContent || '{}');
    } catch (error) {
      run = {};
      script = [
        { speaker: 'console', type: 'line', text: 'validation-run-data could not be parsed; using fallback replay' },
        ...fallbackScript({ result_label: 'Evidence Incomplete' }),
      ];
      return;
    }
    const supplied = run.evidence && Array.isArray(run.evidence.walkthrough_script) ? run.evidence.walkthrough_script : [];
    script = supplied.length >= 5 ? supplied : fallbackScript(run);
  };

  const promptFor = (item) => {
    if (['command', 'replay', 'warning'].includes(item.type)) return '';
    return `${(item.speaker || 'console').toLowerCase()}>`;
  };

  const typeInto = (node, value, done) => {
    const text = String(value || '');
    let offset = 0;
    typing = true;
    const tick = () => {
      node.textContent = text.slice(0, offset);
      offset += 1;
      lines.scrollTop = lines.scrollHeight;
      if (offset <= text.length) {
        window.setTimeout(tick, Math.min(18, 6 + Math.floor(text.length / 18)));
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
    showControls();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'terminal-action';
    button.textContent = 'Restart';
    button.addEventListener('click', startTerminal);
    controls.replaceChildren(button);
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

  const submitControl = (item, rawValue) => {
    const value = cleanControlText(rawValue);
    if (value === 'RESTART') {
      startTerminal();
      return;
    }
    if (!allowedControls.has(value) || value !== item.expected) {
      appendLine({ speaker: 'console', type: 'line', text: 'Unknown replay control. Use ANALYZE, REQUEST, AUTH, or FIX.' }, () => showControl(item));
      return;
    }
    appendLine({ speaker: 'input', type: 'line', text: value }, advance);
  };

  const showControl = (item) => {
    if (item.type !== 'control') {
      window.setTimeout(advance, ['command', 'replay'].includes(item.type) ? 420 : 220);
      return;
    }
    showControls();
    const form = document.createElement('form');
    form.className = 'terminal-input-form';
    const prompt = document.createElement('span');
    prompt.className = 'console-prompt';
    prompt.textContent = 'input>';
    const input = document.createElement('input');
    input.type = 'text';
    input.name = 'replay_control';
    input.maxLength = 16;
    input.autocomplete = 'off';
    input.placeholder = item.expected;
    const button = document.createElement('button');
    button.type = 'submit';
    button.className = 'terminal-action';
    button.textContent = 'Enter';
    form.append(prompt, input, button);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      clearControls();
      submitControl(item, input.value);
    });
    controls.replaceChildren(form);
    input.focus();
  };

  function startTerminal() {
    loadScript();
    index = 0;
    typing = false;
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
