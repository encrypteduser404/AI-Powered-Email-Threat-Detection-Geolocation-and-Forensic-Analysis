import { Download, Flag } from 'lucide-react'
import { SeverityBadge } from '../ui/SeverityBadge'
import type { AnalysisResult } from '../../types/analysis'
import { Link } from 'react-router-dom'

interface InvestigationHeaderProps { result: AnalysisResult; onReviewed: () => void; reviewed: boolean }

export function InvestigationHeader({ result, onReviewed, reviewed }: InvestigationHeaderProps) {
  return <div className="investigation-header"><div><p className="eyebrow">Case {result.incidentId}</p><h1>Investigation Workspace</h1><p className="page-description">Review message evidence, authentication results, extracted indicators, infrastructure intelligence and recommended response actions.</p></div><div className="investigation-header-meta"><div><SeverityBadge severity={result.severity} /><strong className="risk-header">Risk {result.riskScore}/100</strong><small>Analyzed {result.analyzedAt}</small></div><div className="page-actions"><Link className="button button-secondary" to={`/reports/${result.incidentId}`}><Download size={15} />Export report</Link><button className={`button ${reviewed ? 'button-reviewed' : 'button-primary'}`} onClick={onReviewed}><Flag size={15} />{reviewed ? 'Reviewed' : 'Mark reviewed'}</button></div></div></div>
}