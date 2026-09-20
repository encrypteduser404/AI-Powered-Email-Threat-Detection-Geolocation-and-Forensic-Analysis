import { FileText } from 'lucide-react'
import { PageHeader } from '../components/ui/PageHeader'

export function Reports() { return <><PageHeader eyebrow="Case Management" title="Investigation Reports" description="Review and export findings from completed investigations." /><section className="empty-workspace"><div className="empty-icon"><FileText size={24} /></div><h2>No reports generated</h2><p>Completed investigation reports will appear here for review and export.</p></section></> }