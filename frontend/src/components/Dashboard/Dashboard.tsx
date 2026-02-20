import { useNavigate } from 'react-router-dom';
import {
  Radar,
  Server,
  Wifi,
  CheckCircle2,
  ArrowRight,
  Shield,
  AlertTriangle,
} from 'lucide-react';
import { dashboardApi } from '../../api/client';
import { useFetch, usePolling } from '../../hooks/useData';
import { formatRelative } from '../../utils/formatters';
import type { DashboardStats } from '../../types';

function Dashboard() {
  const navigate = useNavigate();
  const { data: stats, loading, reload } = useFetch<DashboardStats>(dashboardApi.stats);

  usePolling(reload, 10000);

  if (loading && !stats) {
    return (
      <div className="loading-overlay">
        <div className="spinner" />
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="empty-state">
        <Radar size={48} />
        <div className="empty-state-title">No Data Yet</div>
        <div className="empty-state-text">
          Run your first network scan to populate the dashboard.
        </div>
        <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={() => navigate('/scans')}>
          <Radar size={16} /> Launch Scan
        </button>
      </div>
    );
  }

  const maxService = stats.top_services.length ? Math.max(...stats.top_services.map(s => s.count)) : 1;
  const maxPort = stats.top_ports.length ? Math.max(...stats.top_ports.map(p => p.count)) : 1;
  const maxOs = stats.os_distribution.length ? Math.max(...stats.os_distribution.map(o => o.count)) : 1;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Network discovery overview and statistics</p>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/scans')}>
          <Radar size={16} /> New Scan
        </button>
      </div>

      {/* ── Stats Grid ─────────────────── */}
      <div className="stats-grid">
        <StatCard
          label="Total Scans"
          value={stats.scans.total}
          sub={`${stats.scans.running} running`}
          icon={<Radar size={20} />}
          color="blue"
        />
        <StatCard
          label="Live Hosts"
          value={stats.hosts.live}
          sub={`${stats.hosts.unique_ips} unique IPs`}
          icon={<Server size={20} />}
          color="green"
        />
        <StatCard
          label="Open Ports"
          value={stats.ports.open}
          sub={`${stats.ports.total} total detected`}
          icon={<Wifi size={20} />}
          color="amber"
        />
        <StatCard
          label="Completed"
          value={stats.scans.completed}
          sub={`${stats.scans.failed} failed`}
          icon={<CheckCircle2 size={20} />}
          color="green"
        />
      </div>

      {/* ── Firmware Stats Row ──────────── */}
      {stats.firmware && (
        <div className="stats-grid" style={{ marginBottom: 16 }}>
          <StatCard
            label="FW Analyses"
            value={stats.firmware.total}
            sub={`${stats.firmware.running} running`}
            icon={<Shield size={20} />}
            color="purple"
          />
          <StatCard
            label="FW Completed"
            value={stats.firmware.completed}
            sub={`${stats.firmware.hosts_with_firmware_url} hosts analysed`}
            icon={<CheckCircle2 size={20} />}
            color="green"
          />
          <StatCard
            label="Avg Risk Score"
            value={Number((stats.firmware.avg_risk_score ?? 0).toFixed(1))}
            sub={`max ${(stats.firmware.max_risk_score ?? 0).toFixed(1)}`}
            icon={<AlertTriangle size={20} />}
            color={(stats.firmware.avg_risk_score ?? 0) > 7 ? 'red' : (stats.firmware.avg_risk_score ?? 0) > 4 ? 'amber' : 'green'}
          />
        </div>
      )}

      {/* ── Two-column content ──────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* Recent Scans */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Recent Scans</span>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/scans')}>
              View All <ArrowRight size={14} />
            </button>
          </div>
          <div className="panel-body no-pad">
            {stats.recent_scans.length === 0 ? (
              <div className="empty-state" style={{ padding: 32 }}>
                <div className="empty-state-text">No scans yet</div>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Hosts</th>
                    <th>Ports</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_scans.map((s) => (
                    <tr
                      key={s.id}
                      className="clickable-row"
                      onClick={() => navigate(`/scans/${s.id}`)}
                    >
                      <td className="mono">{s.target}</td>
                      <td>
                        <span className={`badge badge-${s.status}`}>
                          <span className="badge-dot" />
                          {s.status}
                        </span>
                      </td>
                      <td>{s.hosts_discovered}</td>
                      <td>{s.open_ports_found}</td>
                      <td className="text-muted text-sm">{formatRelative(s.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Top Services */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Top Services</span>
          </div>
          <div className="panel-body">
            {stats.top_services.length === 0 ? (
              <div className="text-muted text-sm">No services detected yet</div>
            ) : (
              <div className="dist-list">
                {stats.top_services.map((s) => (
                  <div key={s.name} className="dist-item">
                    <span className="dist-label">{s.name}</span>
                    <div className="dist-bar-wrap">
                      <div
                        className="dist-bar"
                        style={{ width: `${(s.count / maxService) * 100}%` }}
                      />
                    </div>
                    <span className="dist-count">{s.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Top Ports */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Top Open Ports</span>
          </div>
          <div className="panel-body">
            {stats.top_ports.length === 0 ? (
              <div className="text-muted text-sm">No ports detected yet</div>
            ) : (
              <div className="dist-list">
                {stats.top_ports.map((p) => (
                  <div key={p.port} className="dist-item">
                    <span className="dist-label mono">{p.port}</span>
                    <div className="dist-bar-wrap">
                      <div
                        className="dist-bar"
                        style={{ width: `${(p.count / maxPort) * 100}%`, background: 'var(--accent-amber)' }}
                      />
                    </div>
                    <span className="dist-count">{p.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* OS Distribution */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">OS Distribution</span>
          </div>
          <div className="panel-body">
            {stats.os_distribution.length === 0 ? (
              <div className="text-muted text-sm">No OS data yet</div>
            ) : (
              <div className="dist-list">
                {stats.os_distribution.map((o) => (
                  <div key={o.os} className="dist-item">
                    <span className="dist-label">{o.os}</span>
                    <div className="dist-bar-wrap">
                      <div
                        className="dist-bar"
                        style={{ width: `${(o.count / maxOs) * 100}%`, background: 'var(--accent-purple)' }}
                      />
                    </div>
                    <span className="dist-count">{o.count}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Stat Card sub-component ─────────────────── */
interface StatCardProps {
  label: string;
  value: number;
  sub: string;
  icon: React.ReactNode;
  color: string;
}

function StatCard({ label, value, sub, icon, color }: StatCardProps) {
  return (
    <div className={`card stat-card ${color}`}>
      <div className={`stat-icon ${color}`}>{icon}</div>
      <div className="card-title">{label}</div>
      <div className="card-value">{value.toLocaleString()}</div>
      <div className="card-sub">{sub}</div>
    </div>
  );
}

export default Dashboard;
