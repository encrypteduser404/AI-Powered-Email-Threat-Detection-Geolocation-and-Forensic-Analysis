import { useState } from 'react'
import { Eraser } from 'lucide-react'

interface EmailPasteAreaProps { value: string; onChange: (value: string) => void }

export function EmailPasteArea({ value, onChange }: EmailPasteAreaProps) { const [focused, setFocused] = useState(false); const lines = value ? value.split('\n').length : 0; return <div className="paste-area-wrap"><textarea className={`paste-area ${focused ? 'is-focused' : ''}`} value={value} onChange={(event) => onChange(event.target.value)} onFocus={() => setFocused(true)} onBlur={() => setFocused(false)} placeholder={'From: sender@example.com\nTo: analyst@example.com\nSubject: Suspicious message\n\nPaste the complete raw RFC-style email here...'} aria-label="Raw email content" /><div className="paste-footer"><span>{value.length.toLocaleString()} characters · {lines} lines</span><button className="clear-button" onClick={() => onChange('')} disabled={!value}><Eraser size={13} />Clear</button></div></div> }