import { Activity, FileSearch, FileText, LayoutDashboard, Settings, ShieldCheck, X } from 'lucide-react'
import { NavLink } from 'react-router-dom'

interface SidebarProps { isOpen: boolean; onClose: () => void }

const navigation = [
  { label: 'Dashboard', to: '/dashboard', icon: LayoutDashboard },
  { label: 'Analyze Email', to: '/analyze', icon: FileSearch },
  { label: 'Investigations', to: '/investigation/INV-2048', icon: ShieldCheck },
  { label: 'Reports', to: '/reports', icon: FileText },
]

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  return <>
    <button className={`sidebar-backdrop ${isOpen ? 'is-visible' : ''}`} aria-label="Close navigation" onClick={onClose} />
    <aside className={`sidebar ${isOpen ? 'is-open' : ''}`}>
      <div className="sidebar-header"><NavLink className="brand" to="/dashboard" onClick={onClose}><span className="brand-mark">E</span><span><strong>ECHO</strong><small>Email Threat Intelligence</small></span></NavLink><button className="icon-button sidebar-close" aria-label="Close navigation" onClick={onClose}><X size={18} /></button></div>
      <nav className="sidebar-nav" aria-label="Primary navigation"><p className="nav-label">Operations</p>{navigation.map(({ label, to, icon: Icon }) => <NavLink key={to} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} to={to} onClick={onClose}><Icon size={17} strokeWidth={1.8} /><span>{label}</span></NavLink>)}<p className="nav-label nav-label-system">System</p><NavLink className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`} to="/settings" onClick={onClose}><Settings size={17} strokeWidth={1.8} /><span>Settings</span></NavLink></nav>
      <div className="sidebar-footer"><div className="system-status"><span className="status-dot" /><span><strong>System operational</strong><small>All services responding</small></span><Activity size={15} className="status-activity" /></div><p className="sidebar-version">ECHO CORE <span>v0.1.0</span></p></div>
    </aside>
  </>
}