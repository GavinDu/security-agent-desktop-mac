import { invoke } from '@tauri-apps/api/core';

interface Completion {
  message: string;
  finish_reason: 'stop' | 'length';
}

const MAX_PROMPT_BYTES = 16 * 1024;

function safeError(error: unknown): string {
  switch (error) {
    case 'No local inference provider configured':
      return 'No local model configured. Select one at application startup.';
    case 'Invalid model prompt':
      return 'Enter a nonempty prompt of at most 16 KiB.';
    case 'Local inference capacity exceeded':
      return 'Local model is busy. Try again.';
    case 'Local inference provider timed out':
      return 'Local model timed out. Try again.';
    default:
      return 'Local inference unavailable. Check the configured model and retry.';
  }
}

/** No history or tools. The user must explicitly submit the current text. */
export function mountLocalChat(): void {
  const anchor = document.querySelector('main > section');
  if (!anchor) return;
  const panel = document.createElement('section');
  panel.className = 'panel';
  const heading = document.createElement('h2');
  heading.textContent = 'Local model chat';
  const notice = document.createElement('p');
  notice.className = 'muted';
  notice.textContent =
    'Only the current prompt is sent to your configured local model server. That server may log or relay data. No tools or chat history are sent.';
  const label = document.createElement('label');
  label.htmlFor = 'localChatPrompt';
  label.textContent = 'Prompt';
  const prompt = document.createElement('textarea');
  prompt.id = 'localChatPrompt';
  prompt.rows = 4;
  prompt.maxLength = MAX_PROMPT_BYTES;
  prompt.style.width = '100%';
  const send = document.createElement('button');
  send.type = 'button';
  send.textContent = 'Send to local model';
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.textContent = 'Ready for a prompt.';
  const answer = document.createElement('pre');
  answer.setAttribute('aria-label', 'Model answer');
  answer.setAttribute('aria-live', 'polite');
  panel.append(heading, notice, label, prompt, send, status, answer);
  anchor.after(panel);

  let active = false;
  send.addEventListener('click', async () => {
    if (active) return;
    const message = prompt.value;
    if (!message.trim() || new TextEncoder().encode(message).length > MAX_PROMPT_BYTES) {
      status.textContent = 'Enter a nonempty prompt of at most 16 KiB.';
      return;
    }
    active = true;
    send.disabled = true;
    prompt.disabled = true;
    answer.textContent = '';
    status.textContent = 'Waiting for local model…';
    try {
      const completion = await invoke<Completion>('chat_text', { message });
      if (!completion || typeof completion.message !== 'string' ||
          !['stop', 'length'].includes(completion.finish_reason)) {
        throw new Error('Invalid native response');
      }
      answer.textContent = completion.message;
      status.textContent = completion.finish_reason === 'length'
        ? 'Answer reached the model output limit.'
        : 'Answer received.';
    } catch (error) {
      status.textContent = safeError(error);
    } finally {
      active = false;
      send.disabled = false;
      prompt.disabled = false;
    }
  });
}
