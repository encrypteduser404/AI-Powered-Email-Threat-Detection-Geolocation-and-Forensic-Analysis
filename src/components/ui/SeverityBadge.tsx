export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'
interface SeverityBadgeProps { severity: Severity }

export function SeverityBadge({ severity }: SeverityBadgeProps) { return <span className={`severity-badge severity-${severity.toLowerCase()}`}><span className="severity-marker" />{severity}</span> }