import type { AnalysisResult, AnalysisSeverity, AuthenticationResult, EmailMetadata } from '../types/analysis'
import type { ForensicReport } from '../types/report'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'
const REQUEST_TIMEOUT_MS = 15_000

export class ApiError extends Error {
  readonly status: number | null

  constructor(message: string, status: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

interface BackendFinding { title: string; description: string; evidence: string; severity: string; risk_contribution: number }
interface BackendResponse {
  incident_id: string
  risk_score: number
  severity: string
  threat_type: string
  metadata: { from_address: string | null; to: string[]; cc: string[]; bcc: string[]; reply_to: string[]; return_path: string | null; subject: string | null; date: string | null; message_id: string | null }
  authentication: { spf: string; dkim: string; dmarc: string }
  urls: Array<{ url: string; indicators: string[]; status: string; risk_contribution: number }>
  attachments: Array<{ filename: string; content_type: string; size_bytes: number; sha256: string; status: string }>
  findings: BackendFinding[]
  indicators: Array<{ type: string; value: string; source: string; status: string }>
  timeline: Array<{ label: string; timestamp: string; detail: string }>
  geolocation: null
  recommendations: string[]
  analyzed_at: string
}

function isRecord(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null }
function isBackendResponse(value: unknown): value is BackendResponse {
  if (!isRecord(value)) return false
  return typeof value.incident_id === 'string' && typeof value.risk_score === 'number' && typeof value.threat_type === 'string' && isRecord(value.metadata) && isRecord(value.authentication) && Array.isArray(value.urls) && Array.isArray(value.attachments) && Array.isArray(value.findings) && Array.isArray(value.indicators) && Array.isArray(value.timeline) && Array.isArray(value.recommendations) && typeof value.analyzed_at === 'string'
}

function titleCaseSeverity(value: string): AnalysisSeverity {
  const normalized = value.toUpperCase()
  if (normalized === 'CRITICAL') return 'Critical'
  if (normalized === 'HIGH') return 'High'
  if (normalized === 'MEDIUM') return 'Medium'
  return 'Low'
}

function authenticationState(value: string): AuthenticationResult[keyof AuthenticationResult] {
  const normalized = value.toUpperCase()
  if (normalized === 'PASS') return 'Pass'
  if (normalized === 'FAIL') return 'Fail'
  if (normalized === 'NEUTRAL') return 'Neutral'
  return 'Unknown'
}

function mapMetadata(metadata: BackendResponse['metadata']): EmailMetadata {
  return { from: metadata.from_address ?? 'Unavailable', to: metadata.to.join(', ') || 'Unavailable', subject: metadata.subject ?? 'Unavailable', date: metadata.date ?? 'Unavailable', messageId: metadata.message_id ?? 'Unavailable', attachmentCount: 0, urlCount: 0, replyTo: metadata.reply_to.join(', ') || undefined, returnPath: metadata.return_path ?? undefined }
}

function mapResponse(payload: BackendResponse): AnalysisResult {
  const metadata = mapMetadata(payload.metadata)
  metadata.attachmentCount = payload.attachments.length
  metadata.urlCount = payload.urls.length
  return {
    incidentId: payload.incident_id,
    riskScore: payload.risk_score,
    severity: titleCaseSeverity(payload.severity),
    threatType: payload.threat_type,
    metadata,
    authentication: { spf: authenticationState(payload.authentication.spf), dkim: authenticationState(payload.authentication.dkim), dmarc: authenticationState(payload.authentication.dmarc) },
    urls: payload.urls.map((url) => ({ value: url.url, verdict: url.status === 'BENIGN' ? 'Clean' : url.status === 'SUSPICIOUS' ? 'Suspicious' : 'Unknown', reason: url.indicators.join(', ') || undefined })),
    attachments: payload.attachments.map((attachment) => ({ name: attachment.filename, type: attachment.content_type, verdict: attachment.status === 'SUSPICIOUS' ? 'Suspicious' : 'Unknown', size: `${attachment.size_bytes} bytes`, sha256: attachment.sha256 })),
    findings: payload.findings.map((finding) => ({ title: finding.title, detail: `${finding.description} Evidence: ${finding.evidence}`, severity: titleCaseSeverity(finding.severity), riskContribution: finding.risk_contribution })),
    indicators: payload.indicators.map((indicator) => ({ type: indicator.type === 'IP' ? 'IP address' : indicator.type === 'HASH' ? 'Hash' : indicator.type === 'EMAIL' ? 'Email' : indicator.type === 'URL' ? 'URL' : 'Domain', value: indicator.value, source: indicator.source, status: indicator.status === 'SUSPICIOUS' ? 'Review' : indicator.status === 'UNKNOWN' ? 'Unknown' : 'Observed' })),
    timeline: payload.timeline,
    geolocation: null,
    recommendations: payload.recommendations,
    analyzedAt: payload.analyzed_at,
    rawContent: '',
  }
}

export async function analyzeEmail(file: File): Promise<AnalysisResult> {
  const formData = new FormData()
  formData.append('file', file)
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const response = await fetch(`${API_BASE_URL}/api/analyze`, { method: 'POST', body: formData, signal: controller.signal })
    const body: unknown = await response.json().catch(() => null)
    if (!response.ok) {
      const detail = isRecord(body) && typeof body.detail === 'string' ? body.detail : `Analysis service returned HTTP ${response.status}.`
      throw new ApiError(detail, response.status)
    }
    if (!isBackendResponse(body)) throw new ApiError('Analysis service returned an unexpected response.')
    return mapResponse(body)
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (error instanceof DOMException && error.name === 'AbortError') throw new ApiError('Analysis request timed out.')
    throw new ApiError('Unable to reach the ECHO analysis engine.')
  } finally {
    window.clearTimeout(timeout)
  }
}

export async function getForensicReport(incidentId: string): Promise<ForensicReport> {
  const response = await fetch(`${API_BASE_URL}/api/reports/${encodeURIComponent(incidentId)}`)
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const detail = isRecord(body) && typeof body.detail === 'string' ? body.detail : `Report service returned HTTP ${response.status}.`
    throw new ApiError(detail, response.status)
  }
  if (!isRecord(body) || typeof body.report_id !== 'string' || !isRecord(body.evidence_provenance) || !isRecord(body.incident)) throw new ApiError('Report service returned an unexpected response.')
  const report = body as unknown as Omit<ForensicReport, 'authentication' | 'url_evidence' | 'attachment_evidence' | 'findings'> & { authentication: { results: Record<string, string>; raw_evidence: string[]; note: string }; url_evidence: Array<Record<string, unknown>>; attachment_evidence: Array<Record<string, unknown>>; findings: Array<{ id?: string; category?: string; title: string; severity: string; description: string; evidence: string; risk_contribution: number }> }
  return {
    ...report,
    authentication: { ...report.authentication, results: Object.fromEntries(Object.entries(report.authentication.results).map(([key, value]) => [key, authenticationState(String(value))])) as unknown as ForensicReport['authentication']['results'] },
    url_evidence: report.url_evidence.map((url) => ({ url: String(url.url), domain: String(url.domain), scheme: String(url.scheme), indicators: Array.isArray(url.indicators) ? url.indicators.map(String) : [], status: String(url.status), risk_contribution: Number(url.risk_contribution ?? 0) })),
    attachment_evidence: report.attachment_evidence.map((attachment) => ({ filename: String(attachment.filename), content_type: String(attachment.content_type), size_bytes: Number(attachment.size_bytes ?? 0), sha256: String(attachment.sha256), indicators: Array.isArray(attachment.indicators) ? attachment.indicators.map(String) : [], status: String(attachment.status) })),
    findings: report.findings.map((finding) => ({ id: String(finding.id ?? ''), category: String(finding.category ?? ''), title: String(finding.title), detail: String(finding.description ?? ''), evidence: String(finding.evidence ?? ''), severity: titleCaseSeverity(String(finding.severity)), riskContribution: Number(finding.risk_contribution ?? 0) })),
  }
}