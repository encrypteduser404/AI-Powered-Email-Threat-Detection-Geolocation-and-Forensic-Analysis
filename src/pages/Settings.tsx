import { Settings2 } from 'lucide-react'
import { PageHeader } from '../components/ui/PageHeader'

export function Settings() { return <><PageHeader eyebrow="Platform Administration" title="System Configuration" description="Manage platform preferences and analyst workspace settings." /><section className="empty-workspace"><div className="empty-icon"><Settings2 size={24} /></div><h2>Configuration controls</h2><p>System preferences, notification rules and analyst access controls will appear here.</p></section></> }