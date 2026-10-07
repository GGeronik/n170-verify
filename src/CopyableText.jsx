import { useRef, useState } from 'react';
import { download } from './ui.jsx';

// The visible text is the exact clipboard/download payload. Failure leaves a
// keyboard-accessible selection instead of pretending that the copy succeeded.
export default function CopyableText({ id, title, text, action, fileName, busy = false }) {
  const box = useRef(null);
  const [status, setStatus] = useState('');
  function select() { box.current?.focus(); box.current?.select(); setStatus('Text selected. Copy it using your keyboard or device menu.'); }
  async function copy() {
    try { await navigator.clipboard.writeText(text); setStatus('Copied. Review the text before sending it yourself.'); }
    catch { select(); setStatus('Clipboard unavailable. Copy the selected text, or download it.'); }
  }
  return <div className="copyable-text">
    <div className="prompt-card"><div className="prompt-toolbar"><label htmlFor={id}>{title}</label><button className="button secondary" disabled={busy} onClick={copy}>{action}</button></div>
      <textarea id={id} className="assistant-prompt" ref={box} readOnly value={text} spellCheck="false" aria-describedby={`${id}-status`}/>
      <div className="prompt-footer"><span>Exactly what will be copied</span><button className="text-button" onClick={select}>Select text</button><button className="text-button" onClick={()=>download(text,fileName,'text/plain')}>Download text</button></div>
    </div><p id={`${id}-status`} className="copy-status" role="status">{status || 'Nothing is sent by Verify.'}</p>
  </div>;
}
