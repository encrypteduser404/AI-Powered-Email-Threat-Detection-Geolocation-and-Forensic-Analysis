import { Bell, ChevronRight, Menu } from 'lucide-react'
import { useLocation } from 'react-router-dom'

interface TopbarProps { onMenuClick: () => void }

const titles: Record<string, string> = { '/dashboard': 'Dashboard', '/analyze': 'Analyze Email', '/reports': 'Reports', '/settings': 'Settings' }

export function Topbar({ onMenuClick }: TopbarProps) {
  const { pathname } = useLocation()
  const title = titles[pathname] ?? (pathname.startsWith('/investigation/') ? 'Investigation Workspace' : 'Dashboard')
  return <header className="topbar"><div className="topbar-left"><button className="icon-button menu-button" aria-label="Open navigation" onClick={onMenuClick}><Menu size={20} /></button><span className="breadcrumb-root">ECHO</span><ChevronRight size={14} className="breadcrumb-chevron" /><span className="breadcrumb-current">{title}</span></div><div className="topbar-right"><div className="topbar-system"><span className="status-dot" /><span>Operational</span></div><button className="icon-button notification-button" aria-label="View notifications"><Bell size={18} /><span className="notification-dot" /></button><div className="analyst-profile"><span className="profile-mark">AS</span><span><strong>ANALYST</strong><small>Security Operations</small></span></div></div></header>
}