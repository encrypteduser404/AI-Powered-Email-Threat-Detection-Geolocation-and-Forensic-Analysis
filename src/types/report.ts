import type { AnalysisTimelineEvent, AuthenticationResult, AnalysisFinding, AnalysisIndicator } from './analysis'

export interface ReportFootprint {
  evidence_id: string
  incident_id: string
  source: { filename: string; media_type: string; size_bytes: number; sha256: string }
  processing: { received_at: string; analysis_started_at: string; analysis_completed_at: string; parser_version: string; analysis_engine_version: string }
  message: { sender: string | null; recipients: string[]; subject: string | null; message_id: string | null; date: string | null; reply_to: string[]; return_path: string | null }
  header_evidence: { received_hops: string[]; authentication_headers: string[] }
  network_evidence: { observed_ips: string[]; observed_domains: string[]; observed_urls: string[] }
  artifact_evidence: { attachments: string[]; attachment_hashes: string[] }
  integrity: { original_email_sha256: string; evidence_manifest_sha256: string }
}

export interface ForensicReport {
  report_id: string
  generated_at: string
  incident: { incident_id: string; risk_score: number; severity: string; threat_type: string }
  executive_summary: string
  evidence_provenance: ReportFootprint
  email_metadata: ReportFootprint['message']
  authentication: { results: AuthenticationResult; raw_evidence: string[]; note: string }
  routing: ReportFootprint['header_evidence']
  url_evidence: Array<{ url: string; domain: string; scheme: string; indicators: string[]; status: string; risk_contribution: number }>
  attachment_evidence: Array<{ filename: string; content_type: string; size_bytes: number; sha256: string; indicators: string[]; status: string }>
  ioc_manifest: AnalysisIndicator[]
  findings: AnalysisFinding[]
  infrastructure: null
  forensic_timeline: AnalysisTimelineEvent[]
  recommendations: string[]
  analyst_notes: string
  integrity: ReportFootprint['integrity']
}