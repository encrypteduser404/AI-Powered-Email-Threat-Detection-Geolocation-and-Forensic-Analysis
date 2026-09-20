import { CircleAlert, CircleCheck, CircleDashed, LoaderCircle } from 'lucide-react'

export type Status = 'Operational' | 'Processing' | 'Failed' | 'Unknown'
interface StatusBadgeProps { status: Status }
const statusIcons = { Operational: CircleCheck, Processing: LoaderCircle, Failed: CircleAlert, Unknown: CircleDashed }

export function StatusBadge({ status }: StatusBadgeProps) { const Icon = statusIcons[status]; return <span className={`status-badge status-${status.toLowerCase()}`}><Icon size={13} />{status}</span> }