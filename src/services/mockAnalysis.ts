import { demoEmails } from '../data/demoEmails'
import type { AnalysisResult, DemoEmail } from '../types/analysis'
import { storeAnalysisResult } from './analysisStore'

const analysisResults = new Map<string, AnalysisResult>()

function createMockAnalysis(email: DemoEmail): AnalysisResult {
  const isBenign = email.id === 'benign-message'
  const isPhishing = email.id === 'credential-phishing'
  const incidentId = email.id === 'credential-phishing' ? 'INV-2048' : `INC-${email.id.slice(0, 3).toUpperCase()}-${Date.now().toString().slice(-5)}`
  return {
    incidentId,
    riskScore: isBenign ? 8 : isPhishing ? 96 : 78,
    severity: email.threatLevel,
    threatType: isBenign ? 'Routine communication' : email.title,
    metadata: { ...email.metadata, replyTo: isPhishing ? 'helpdesk@micros0ft-support.com' : undefined, returnPath: `bounce@${email.domain}` },
    authentication: { spf: isBenign ? 'Pass' : 'Fail', dkim: isBenign ? 'Pass' : 'Neutral', dmarc: isBenign ? 'Pass' : 'Fail' },
    urls: email.metadata.urlCount > 0 ? [{ value: isPhishing ? 'https://login-micros0ft-support.com/verify' : 'https://status.echo.local/maintenance', verdict: isBenign ? 'Clean' : 'Malicious', reason: isBenign ? 'Internal status domain' : 'Lookalike domain and unusual verification path' }] : [],
    attachments: email.metadata.attachmentCount > 0 ? [{ name: email.id === 'malicious-attachment' ? 'delivery_exception.xlsm' : 'INV-8841.pdf', type: 'application/octet-stream', verdict: email.id === 'malicious-attachment' ? 'Malicious' : 'Suspicious', size: email.id === 'malicious-attachment' ? '84 KB' : '218 KB', sha256: 'a83b7b1c4e77d7c62b4fd8191d3c8f65b7c0e7b1a4f0190c8e5a77f0a2b6c911' }] : [],
    findings: isBenign ? [{ title: 'No material threat signals', detail: 'Sender identity and content are consistent with internal maintenance communications.', severity: 'Low', riskContribution: 0 }] : [{ title: email.evidence, detail: 'The signal requires analyst review before the message is released.', severity: email.threatLevel, riskContribution: isPhishing ? 25 : 20 }, { title: 'Sender trust is reduced', detail: 'One or more identity or content checks did not align with the expected sender profile.', severity: 'Medium', riskContribution: 15 }],
    indicators: [{ type: 'Domain', value: email.domain, source: 'Header analysis', status: isBenign ? 'Clean' : 'Review' }, ...(isPhishing ? [{ type: 'URL' as const, value: 'login-micros0ft-support.com', source: 'URL extraction', status: 'Review' as const }] : [])],
    timeline: [{ label: 'Message received', timestamp: email.metadata.date, detail: 'Message accepted for local inspection' }, { label: 'Analysis completed', timestamp: 'Just now', detail: 'Mock analysis pipeline completed' }],
    geolocation: { country: isBenign ? 'India' : 'Netherlands', city: isBenign ? 'Bengaluru' : 'Amsterdam', region: isBenign ? 'Karnataka' : 'North Holland', organization: isBenign ? 'ECHO Internal Network' : 'Transit Hosting B.V.', asn: isBenign ? 'AS64512' : 'AS204957', domain: email.domain, ip: isBenign ? '10.24.8.14' : '185.203.118.41' },
    recommendations: isBenign ? ['Close the investigation as benign.', 'Retain message metadata for audit history.'] : ['Quarantine the message and related indicators.', 'Verify the sender through an independent channel.', 'Add confirmed indicators to the monitoring list.'],
    analyzedAt: '19 Sep 2026, 09:43 UTC',
    rawContent: email.rawContent,
  }
}

export async function runMockAnalysis(email: DemoEmail): Promise<AnalysisResult> {
  await new Promise((resolve) => setTimeout(resolve, 300))
  const result = createMockAnalysis(email)
  analysisResults.set(result.incidentId, result)
  storeAnalysisResult(result)
  return result
}

export function getMockAnalysis(incidentId: string): AnalysisResult | null {
  const existing = analysisResults.get(incidentId)
  if (existing) return existing
  if (incidentId === 'INV-2048') return createMockAnalysis(demoEmails[0])
  return null
}