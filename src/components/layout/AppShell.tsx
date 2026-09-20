import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

export function AppShell() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="app-shell">
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="workspace">
        <Topbar onMenuClick={() => setSidebarOpen(true)} />
        <main className="main-content"><div className="page-container"><Outlet /></div></main>
      </div>
    </div>
  )
}