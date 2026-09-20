export type AnalysisInputSource = 'Demo case' | 'Uploaded file' | 'Pasted message'
export type AnalysisSeverity = 'Low' | 'Medium' | 'High' | 'Critical'
export type AnalysisStep = 'Uploading message' | 'Parsing email' | 'Analyzing evidence' | 'Building assessment' | 'Parsing message' | 'Inspecting headers' | 'Checking authentication' | 'Extracting URLs' | 'Inspecting attachments' | 'Evaluating threat indicators'

export interface EmailMetadata {
  from: string
  to: string
  subject: string
  date: string
  messageId: string
  attachmentCount: number
  urlCount: number
  replyTo?: string
  returnPath?: string
}

export interface DemoEmail {
  id: string
  title: string
  description: string
  threatLevel: AnalysisSeverity
  sender: string
  domain: string
  evidence: string
  metadata: EmailMetadata
  rawContent: string
}

export interface AuthenticationResult {
  spf: 'Pass' | 'Fail' | 'Neutral' | 'Unknown'
  dkim: 'Pass' | 'Fail' | 'Neutral' | 'Unknown'
  dmarc: 'Pass' | 'Fail' | 'Neutral' | 'Unknown'
}

export interface AnalysisUrl { value: string; verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown'; reason?: string }
export interface AnalysisAttachment { name: string; type: string; verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown'; size?: string; sha256?: string }
export interface AnalysisFinding { id?: string; category?: string; title: string; detail: string; evidence?: string; severity: AnalysisSeverity; riskContribution?: number }
export interface AnalysisIndicator { type: 'Domain' | 'IP address' | 'Hash' | 'URL' | 'Email'; value: string; source?: string; status?: 'Observed' | 'Review' | 'Clean' | 'Unknown' }
export interface AnalysisTimelineEvent { label: string; timestamp: string; detail: string }
export interface Geolocation { country: string; city: string; ip: string; region?: string; organization?: string; asn?: string; domain?: string }

export interface AnalysisResult {
  incidentId: string
  riskScore: number
  severity: AnalysisSeverity
  threatType: string
  metadata: EmailMetadata
  authentication: AuthenticationResult
  urls: AnalysisUrl[]
  attachments: AnalysisAttachment[]
  findings: AnalysisFinding[]
  indicators: AnalysisIndicator[]
  timeline: AnalysisTimelineEvent[]
  geolocation: Geolocation | null
  recommendations: string[]
  analyzedAt: string
  rawContent: string
}