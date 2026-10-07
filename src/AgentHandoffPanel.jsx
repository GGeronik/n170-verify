import { useRef, useState } from 'react';
import instructions from '../docs/agent-instructions.txt?raw';
import { makeAssistantPrompt } from './assistantPrompt.js';
import { download } from './ui.jsx';

const prompt = makeAssistantPrompt(instructions);
export default function AgentHandoffPanel({ value, onChange, onOpen, onFile, prepared, busy }) {
  const promptBox = useRef(null);
  const [copyState, setCopyState] = useState('');
  const [copied, setCopied] = useState(false);
  function selectPrompt() {
    promptBox.current?.focus();
    promptBox.current?.select();
    setCopyState('Full prompt selected. Copy it, then paste it into your AI.');
  }
  async function copyPrompt() {
    try {
      await navigator.clipboard.writeText(prompt);
      setCopied(true);
      setCopyState('Copied. Paste it into the AI where your broker is connected.');
    } catch {
      selectPrompt();
      setCopied(false);
      setCopyState('Clipboard unavailable. Copy the selected text, or download the prompt.');
    }
  }
  const content = <div className="agent-handoff">
    <section className="assistant-step" aria-labelledby="assistant-copy-heading">
      <div className="assistant-step-heading"><span aria-hidden="true">1</span><h3 id="assistant-copy-heading">Copy this prompt to your AI</h3></div>
      <p>Use the AI where your broker is already connected. It will ask which account and dates to include.</p>
      <div className="prompt-card">
        <div className="prompt-toolbar"><label htmlFor="assistant-prompt">Prompt for your AI</label><button className="button primary" disabled={busy} onClick={copyPrompt}>{copied ? 'Copy prompt again' : 'Copy prompt'}<svg width="16" height="16" viewBox="0 0 20 20" fill="none" aria-hidden="true"><rect x="7" y="7" width="10" height="10" rx="1.5" stroke="currentColor"/><path d="M12 4V3H3v9h1" stroke="currentColor" strokeLinecap="round"/></svg></button></div>
        <textarea id="assistant-prompt" className="assistant-prompt" ref={promptBox} readOnly value={prompt} spellCheck="false" aria-describedby="assistant-prompt-help"/>
        <div className="prompt-footer"><span id="assistant-prompt-help">Complete instructions included</span><button className="text-button" onClick={selectPrompt}>Select prompt</button><button className="text-button" onClick={()=>download(prompt,'n170-verify-ai-prompt.txt','text/plain')}>Download prompt</button></div>
      </div>
      <p className="copy-status" role="status">{copyState || 'No setup in Verify. Your AI uses the broker access you already authorized.'}</p>
    </section>
    <section className="assistant-step assistant-return" aria-labelledby="assistant-return-heading">
      <div className="assistant-step-heading"><span aria-hidden="true">2</span><h3 id="assistant-return-heading">Bring its answer back here</h3></div>
      <p>Your AI will prepare a file or reply. Open it here to see the observations and anything that needs attention.</p>
      <label className="button secondary file-label">Choose AI file<input type="file" accept=".json" onChange={onFile} disabled={busy}/></label>
      <label htmlFor="agent-handoff-json">Or paste your AI’s reply</label>
      <textarea id="agent-handoff-json" value={value} onChange={event=>onChange(event.target.value)} maxLength={1000000} disabled={busy} spellCheck="false" placeholder="Paste the prepared JSON here, including a code block if your AI uses one."/>
      <div className="actions"><button className="button primary" disabled={busy || !value.trim()} onClick={onOpen}>{busy ? 'Opening…' : 'Review my record'}<span aria-hidden="true">→</span></button><span className="assistant-return-note">You review before signing or sharing.</span></div>
    </section>
    <details className="assistant-explainer"><summary>What happens to my data?</summary><p>Use broker access with read-only permissions where available. A prompt can request safe behaviour, but it cannot restrict a connected tool’s permissions. Review any access request in your AI before continuing.</p><p>Your AI’s privacy settings apply while it gathers data. Only this browser processes the file you bring back. Keep account numbers, passwords and API tokens out of the reply.</p><p>Verify checks the supplied observations and makes missing evidence visible. A file prepared by an AI remains supplied-file evidence: it does not authenticate a broker, confirm your identity or establish account completeness.</p><p><a href="/agent-handoff.md" target="_blank" rel="noreferrer">Guide & limitations</a> · <a href="/agent-handoff-v1.schema.json" download>File format</a> · <a href="/agent-handoff-example.json" download>Synthetic example</a></p></details>
  </div>;
  return prepared ? <details className="assistant-prepared"><summary>Prepare another record with your AI</summary>{content}</details> : content;
}
