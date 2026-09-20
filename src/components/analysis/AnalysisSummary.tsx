import { CheckCircle2, Circle } from 'lucide-react'
import type { AnalysisInputSource } from '../../types/analysis'

interface AnalysisSummaryProps { source: AnalysisInputSource | null; hasInput: boolean }
const signals = ['Headers', 'Authentication', 'URLs', 'Attachments', 'Content']

export function AnalysisSummary({ source, hasInput }: AnalysisSummaryProps) { return <section className="analysis-summary"><div><span>Input source</span><strong>{source ?? 'No input selected'}</strong></div><div className="summary-signals"><span>Signals available</span><div>{signals.map((signal) => <span className="signal" key={signal}>{hasInput ? <CheckCircle2 size={14} /> : <Circle size={14} />}{signal}</span>)}</div></div></section> }