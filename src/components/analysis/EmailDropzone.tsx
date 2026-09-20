import { useRef, type ChangeEvent, type DragEvent } from 'react'
import { FileUp, X } from 'lucide-react'

interface EmailDropzoneProps { file: File | null; error: string; onFile: (file: File | null) => void; onError: (message: string) => void }

function validateFile(file: File | undefined, onFile: (file: File | null) => void, onError: (message: string) => void) {
  if (!file) { onError('Please select an .eml email message.'); return }
  if (!file.name.toLowerCase().endsWith('.eml')) { onFile(null); onError('Unsupported file type. Please select an .eml email message.'); return }
  onError(''); onFile(file)
}

export function EmailDropzone({ file, error, onFile, onError }: EmailDropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const handleChange = (event: ChangeEvent<HTMLInputElement>) => validateFile(event.target.files?.[0], onFile, onError)
  const handleDrop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); validateFile(event.dataTransfer.files[0], onFile, onError) }
  return <div><div className={`dropzone ${error ? 'has-error' : ''} ${file ? 'has-file' : ''}`} onDragOver={(event) => event.preventDefault()} onDrop={handleDrop} onClick={() => inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') inputRef.current?.click() }}><input ref={inputRef} type="file" accept=".eml,message/rfc822" onChange={handleChange} hidden />{file ? <><div className="dropzone-file"><FileUp size={19} /><span><strong>{file.name}</strong><small>{(file.size / 1024).toFixed(1)} KB · Ready for inspection</small></span></div><button className="icon-button" aria-label="Clear selected file" onClick={(event) => { event.stopPropagation(); onFile(null) }}><X size={16} /></button></> : <><div className="dropzone-icon"><FileUp size={20} /></div><strong>Drop an .eml file here</strong><span>or click to browse your device</span><small>RFC 822 email messages only</small></>}</div>{error ? <p className="inline-error">{error}</p> : null}</div>
}