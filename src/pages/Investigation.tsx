import { FileSearch } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { AnalystNotes } from '../components/investigation/AnalystNotes'
import { AttachmentTable } from '../components/investigation/AttachmentTable'
import { AuthenticationPanel } from '../components/investigation/AuthenticationPanel'
import { EmailEvidence } from '../components/investigation/EmailEvidence'
import { FindingList } from '../components/investigation/FindingList'
import { ForensicTimeline } from '../components/investigation/ForensicTimeline'
import { InfrastructurePanel } from '../components/investigation/InfrastructurePanel'
import { InvestigationHeader } from '../components/investigation/InvestigationHeader'
import { IocTable } from '../components/investigation/IocTable'
import { RecommendationPanel } from '../components/investigation/RecommendationPanel'
import { ThreatAssessment } from '../components/investigation/ThreatAssessment'
import { UrlEvidenceTable } from '../components/investigation/UrlEvidenceTable'
import { getStoredAnalysisResult } from '../services/analysisStore'
import { getMockAnalysis } from '../services/mockAnalysis'

export function Investigation() {
	const { id } = useParams<{ id: string }>()
	const [reviewed, setReviewed] = useState(false)
	const result = id ? getStoredAnalysisResult(id) ?? getMockAnalysis(id) : null
	if (!result) return <section className="empty-workspace investigation-not-found"><div className="empty-icon"><FileSearch size={24} /></div><h2>Investigation not found</h2><p>No local analysis record exists for case {id ?? 'Unknown'}.</p><Link className="button button-primary" to="/analyze">Back to Analyze</Link></section>
	return <div className="investigation-layout"><InvestigationHeader result={result} reviewed={reviewed} onReviewed={() => setReviewed(true)} /><ThreatAssessment result={result} /><FindingList result={result} /><div className="investigation-columns"><div><EmailEvidence result={result} /><UrlEvidenceTable result={result} /><AttachmentTable result={result} /></div><div><AuthenticationPanel result={result} /><InfrastructurePanel result={result} /></div></div><IocTable result={result} /><ForensicTimeline result={result} /><div className="investigation-bottom"><RecommendationPanel result={result} /><AnalystNotes reviewed={reviewed} onReviewed={() => setReviewed(true)} /></div></div>
}