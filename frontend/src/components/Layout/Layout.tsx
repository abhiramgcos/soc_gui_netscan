import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Radar,
  Server,
  Shield,
  Download,
  Activity,
} from 'lucide-react';
import type { ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

function Layout({ children }: Props) {
  const location = useLocation();

  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/scans', icon: Radar, label: 'Scans' },
    { to: '/hosts', icon: Server, label: 'Hosts' },
    { to: '/firmware', icon: Shield, label: 'Firmware' },
  ];

  return (
    <div className="app-layout">
      {/* ── Sidebar ─────────────────────── */}
      <aside className="app-sidebar">
        <div className="sidebar-logo">
          <svg width="28" height="28" viewBox="0 0 32 32" fill="none">
            <circle cx="16" cy="16" r="14" stroke="#3b82f6" strokeWidth="2" fill="none" />
            <circle cx="16" cy="16" r="3" fill="#3b82f6" />
            <line x1="16" y1="2" x2="16" y2="8" stroke="#3b82f6" strokeWidth="1.5" />
            <line x1="16" y1="24" x2="16" y2="30" stroke="#3b82f6" strokeWidth="1.5" />
            <line x1="2" y1="16" x2="8" y2="16" stroke="#3b82f6" strokeWidth="1.5" />
            <line x1="24" y1="16" x2="30" y2="16" stroke="#3b82f6" strokeWidth="1.5" />
            <circle cx="8" cy="8" r="2" fill="#10b981" />
            <circle cx="24" cy="8" r="2" fill="#f59e0b" />
            <circle cx="8" cy="24" r="2" fill="#8b5cf6" />
            <circle cx="24" cy="24" r="2" fill="#ef4444" />
          </svg>
          <div>
            <div className="sidebar-logo-text">NetRecon</div>
            <div className="sidebar-logo-sub">Network Discovery</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="sidebar-section-label">Operations</div>
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `sidebar-link${isActive && (to === '/' ? location.pathname === '/' : true) ? ' active' : ''}`
              }
              end={to === '/'}
            >
              <Icon size={18} />
              <span>{label}</span>
            </NavLink>
          ))}

          <div className="sidebar-section-label" style={{ marginTop: 16 }}>Data</div>
          <a href="/api/docs" target="_blank" rel="noopener" className="sidebar-link">
            <Activity size={18} />
            <span>API Docs</span>
          </a>
          <a
            href="/api/export/hosts?format=csv"
            className="sidebar-link"
            download
          >
            <Download size={18} />
            <span>Export Hosts</span>
          </a>
        </nav>

        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: '#10b981',
                display: 'inline-block',
              }}
            />
            <span>System Online</span>
          </div>
          <div style={{ marginTop: 4, fontSize: 10, opacity: 0.6 }}>v1.0.0</div>
        </div>
      </aside>

      {/* ── Main Content ────────────────── */}
      <main className="app-main">
        <div className="app-content">{children}</div>
      </main>
    </div>
  );
}

export default Layout;
