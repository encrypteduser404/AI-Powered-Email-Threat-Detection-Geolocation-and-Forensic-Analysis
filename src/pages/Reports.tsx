import { FileText } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { AuthenticationReport } from '../components/report/AuthenticationReport'
import { EmailMetadataReport } from '../components/report/EmailMetadataReport'
import { EvidenceProvenance } from '../components/report/EvidenceProvenance'
import { ExecutiveSummary } from '../components/report/ExecutiveSummary'
import { EvidenceTables, IocManifest, RoutingEvidence, UrlEvidenceReport, AttachmentEvidenceReport } from '../components/report/EvidenceTables'
import { FindingsReport } from '../components/report/FindingsReport'
import { ForensicTimelineReport, IntegrityManifest } from '../components/report/TimelineAndIntegrity'
import { ReportHeader } from '../components/report/ReportHeader'
import { PageHeader } from '../components/ui/PageHeader'
import { getForensicReport, ApiError } from '../services/api'
import { getStoredAnalysisResult } from '../services/analysisStore'
import { getMockAnalysis } from '../services/mockAnalysis'
import { createLocalReport } from '../services/localReport'
import type { ForensicReport } from '../types/report'

export function Reports() {
	const { id } = useParams<{ id: string }>()
	const [report, setReport] = useState<ForensicReport | null>(null)
	const [error, setError] = useState('')
	useEffect(() => { if (!id) return; void getForensicReport(id).then(setReport).catch((reason: unknown) => { if (reason instanceof ApiError && reason.status === 404) { const local = getStoredAnalysisResult(id) ?? getMockAnalysis(id); if (local) setReport(createLocalReport(local)); else setError('Forensic report not found') } else setError('Unable to load the forensic report.') }) }, [id])
	if (!id) return <><PageHeader eyebrow="Case Management" title="Investigation Reports" description="Review and export findings from completed investigations." /><section className="empty-workspace"><div className="empty-icon"><FileText size={24} /></div><h2>Select an investigation report</h2><p>Open Export Report from an investigation workspace to view its formal evidence record.</p></section></>
	if (error) return <section className="empty-workspace"><div className="empty-icon"><FileText size={24} /></div><h2>{error}</h2><p>No local report is available for case {id}.</p><Link className="button button-primary" to="/analyze">Back to Analyze</Link></section>
	if (!report) return <section className="empty-workspace"><div className="empty-icon"><FileText size={24} /></div><h2>Loading forensic report</h2><p>Retrieving the structured evidence record.</p></section>
	const exportJson = () => { const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `ECHO_${report.report_id}.json`; link.click(); URL.revokeObjectURL(link.href) }
	const copy = (value: string) => { void navigator.clipboard?.writeText(value) }
	return <div className="report-page"><ReportHeader report={report} onPrint={() => window.print()} onExport={exportJson} /><ExecutiveSummary report={report} /><EvidenceProvenance report={report} onCopy={copy} /><div className="report-columns"><div><EmailMetadataReport report={report} /><RoutingEvidence report={report} /><UrlEvidenceReport report={report} /><AttachmentEvidenceReport report={report} /></div><div><AuthenticationReport report={report} /><EvidenceTables report={report} /></div></div><IocManifest report={report} /><FindingsReport report={report} /><ForensicTimelineReport report={report} /><section className="report-section"><div className="report-section-heading"><div><p className="panel-kicker">Analyst assessment</p><h2>Recommendations and review</h2></div></div><div className="report-section-body"><ul className="report-recommendations">{report.recommendations.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}</ul><p className="report-note">Review status: {report.analyst_notes ? 'Reviewed with analyst notes' : 'Open'}</p></div></section><IntegrityManifest report={report} /></div>
}