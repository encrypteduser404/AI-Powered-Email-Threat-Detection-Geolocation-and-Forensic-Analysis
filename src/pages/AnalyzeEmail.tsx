import { AlertTriangle, Play, RotateCcw } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AnalysisProgress } from '../components/analysis/AnalysisProgress'
import { AnalysisSummary } from '../components/analysis/AnalysisSummary'
import { DemoCaseList } from '../components/analysis/DemoCaseList'
import { EmailDropzone } from '../components/analysis/EmailDropzone'
import { EmailInputTabs } from '../components/analysis/EmailInputTabs'
import { EmailPasteArea } from '../components/analysis/EmailPasteArea'
import { EmailPreview } from '../components/analysis/EmailPreview'
import { PageHeader } from '../components/ui/PageHeader'
import { analyzeEmail, ApiError } from '../services/api'
import { checkBackendHealth } from '../services/health'
import { demoEmails } from '../data/demoEmails'
import { runMockAnalysis } from '../services/mockAnalysis'
import { storeAnalysisResult } from '../services/analysisStore'
import type { AnalysisInputSource, AnalysisStep, DemoEmail, EmailMetadata } from '../types/analysis'

const demoAnalysisSteps: AnalysisStep[] = ['Parsing message', 'Inspecting headers', 'Checking authentication', 'Extracting URLs', 'Inspecting attachments', 'Evaluating threat indicators']
const backendAnalysisSteps: AnalysisStep[] = ['Uploading message', 'Parsing email', 'Analyzing evidence', 'Building assessment']

function metadataFromRaw(rawContent: string, fallback: EmailMetadata): EmailMetadata {
	const getHeader = (name: string) => rawContent.match(new RegExp(`^${name}:\\s*(.+)$`, 'im'))?.[1]?.trim() ?? ''
	return { ...fallback, from: getHeader('From') || fallback.from, to: getHeader('To') || fallback.to, subject: getHeader('Subject') || fallback.subject, date: getHeader('Date') || fallback.date, messageId: getHeader('Message-ID') || fallback.messageId, urlCount: (rawContent.match(/https?:\/\/\S+/gi) ?? []).length }
}

function getSender(from: string) { return from.replace(/^.*<|>$/g, '').trim() }

function createInputEmail(rawContent: string, source: 'Uploaded file' | 'Pasted message', filename?: string): DemoEmail {
	const fallback: EmailMetadata = { from: 'unknown@unverified.local', to: 'analyst@echo.local', subject: filename ? `Uploaded message: ${filename}` : 'Pasted email message', date: 'Not provided', messageId: '<local-message@echo.local>', attachmentCount: 0, urlCount: 0 }
	const metadata = metadataFromRaw(rawContent, fallback)
	const sender = getSender(metadata.from)
	return { id: `local-${source === 'Uploaded file' ? 'upload' : 'paste'}`, title: source, description: 'Local message content ready for inspection.', threatLevel: 'Low', sender, domain: sender.split('@')[1] ?? 'unknown', evidence: 'User-provided message content', metadata, rawContent }
}

export function AnalyzeEmail() {
	const navigate = useNavigate()
	const [mode, setMode] = useState<'upload' | 'paste'>('upload')
	const [file, setFile] = useState<File | null>(null)
	const [fileError, setFileError] = useState('')
	const [pasteContent, setPasteContent] = useState('')
	const [activeEmail, setActiveEmail] = useState<DemoEmail | null>(null)
	const [source, setSource] = useState<AnalysisInputSource | null>(null)
	const [processing, setProcessing] = useState(false)
	const [currentStep, setCurrentStep] = useState(0)
	const [analysisError, setAnalysisError] = useState('')
	const [backendAvailable, setBackendAvailable] = useState<boolean | null>(null)
	const hasInput = Boolean(activeEmail)
	const inputLabel = useMemo(() => source ?? 'No input selected', [source])
	const processingSteps = source === 'Uploaded file' ? backendAnalysisSteps : demoAnalysisSteps

	useEffect(() => { void checkBackendHealth().then(setBackendAvailable) }, [])

	useEffect(() => {
		if (!processing || !activeEmail) return
		let step = 0
		const timer = window.setInterval(() => { step += 1; setCurrentStep(step); if (step >= processingSteps.length) window.clearInterval(timer) }, 400)
		return () => window.clearInterval(timer)
	}, [processing, activeEmail, processingSteps.length])

	useEffect(() => {
		if (!processing || !activeEmail || currentStep < processingSteps.length) return
		let cancelled = false
		const analysis = source === 'Uploaded file' && file ? analyzeEmail(file) : runMockAnalysis(activeEmail)
		void analysis.then((result) => { if (!cancelled) { storeAnalysisResult(result); navigate(`/investigation/${result.incidentId}`) } }).catch((error: unknown) => { if (!cancelled) { setProcessing(false); setAnalysisError(error instanceof ApiError && error.status !== null && error.status >= 400 && error.status < 500 ? error.message : error instanceof ApiError && error.message === 'Unable to reach the ECHO analysis engine.' ? 'Analysis service unavailable. Unable to reach the ECHO analysis engine. Check that the backend is running on port 8000.' : error instanceof ApiError ? error.message : 'Analysis could not be completed. Review the message input and try again.') } })
		return () => { cancelled = true }
	}, [activeEmail, currentStep, file, navigate, processing, processingSteps.length, source])

	const handleFile = async (selectedFile: File | null) => { setFile(selectedFile); setAnalysisError(''); if (!selectedFile) { setActiveEmail(null); setSource(null); return }; const rawContent = await selectedFile.text(); setActiveEmail(createInputEmail(rawContent, 'Uploaded file', selectedFile.name)); setSource('Uploaded file') }
	const handlePaste = (value: string) => { setPasteContent(value); setAnalysisError(''); if (value.trim()) { setActiveEmail(createInputEmail(value, 'Pasted message')); setSource('Pasted message') } else { setActiveEmail(null); setSource(null) } }
	const selectDemo = (email: DemoEmail) => { setMode('upload'); setFile(null); setFileError(''); setPasteContent(''); setActiveEmail(email); setSource('Demo case'); setAnalysisError('') }
	const runAnalysis = () => { if (!activeEmail || processing) return; setAnalysisError(''); setCurrentStep(0); setProcessing(true) }
	const reset = () => { setFile(null); setFileError(''); setPasteContent(''); setActiveEmail(null); setSource(null); setAnalysisError(''); setProcessing(false); setCurrentStep(0) }

	return <>
		<PageHeader eyebrow="Threat Analysis" title="Analyze Email" description="Inspect a suspicious message across headers, authentication, URLs, attachments and content indicators." />
		<div className="analysis-layout">
			<section className="analysis-section intake-section"><div className="section-heading"><div><p className="panel-kicker">Analysis input</p><h2>Select a message to inspect</h2></div><span className="section-count">{backendAvailable === null ? 'Checking analysis engine' : backendAvailable ? 'Backend connected' : 'Backend unavailable'}</span></div><EmailInputTabs mode={mode} onChange={(nextMode) => { setMode(nextMode); setFileError('') }} /><div className="input-body">{mode === 'upload' ? <EmailDropzone file={file} error={fileError} onFile={(nextFile) => void handleFile(nextFile)} onError={setFileError} /> : <EmailPasteArea value={pasteContent} onChange={handlePaste} />}</div></section>
			{activeEmail ? <EmailPreview metadata={activeEmail.metadata} rawContent={activeEmail.rawContent} /> : null}
			<DemoCaseList cases={demoEmails} selectedId={source === 'Demo case' ? activeEmail?.id ?? null : null} onSelect={selectDemo} />
			<AnalysisSummary source={source} hasInput={hasInput} />
			{processing ? <AnalysisProgress currentStep={currentStep} steps={processingSteps} /> : <div className="analysis-actions"><div className="analysis-state">{analysisError ? <><AlertTriangle size={15} /><span>{analysisError}</span></> : hasInput ? <><span className="status-dot" /><span>Message ready for analysis</span></> : <><AlertTriangle size={15} /><span>Select a demo case or provide an email message to continue.</span></>}</div><div className="action-buttons">{hasInput ? <button className="button button-secondary" onClick={reset}><RotateCcw size={15} />Clear</button> : null}<button className="button button-primary run-button" disabled={!hasInput} onClick={runAnalysis}>{analysisError ? 'Retry' : 'Run analysis'} <Play size={15} /></button></div></div>}
			<span className="analysis-source-label">Input source: {inputLabel}</span>
		</div>
	</>
}