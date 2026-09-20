interface EmailInputTabsProps { mode: 'upload' | 'paste'; onChange: (mode: 'upload' | 'paste') => void }

export function EmailInputTabs({ mode, onChange }: EmailInputTabsProps) {
  return <div className="analysis-tabs" role="tablist" aria-label="Email input mode"><button className={mode === 'upload' ? 'active' : ''} role="tab" aria-selected={mode === 'upload'} onClick={() => onChange('upload')}>Upload .EML</button><button className={mode === 'paste' ? 'active' : ''} role="tab" aria-selected={mode === 'paste'} onClick={() => onChange('paste')}>Paste Email</button></div>
}