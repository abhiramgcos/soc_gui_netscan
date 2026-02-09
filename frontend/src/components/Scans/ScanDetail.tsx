import { useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Download,
  Trash2,
  XCircle,
  Server,
  Wifi,
  Clock,
} from 'lucide-react';
import { scansApi, hostsApi, exportApi } from '../../api/client';
import { useFetch, usePolling, useWebSocket } from '../../hooks/useData';
import { formatDate, formatDuration } from '../../utils/formatters';
import type { ScanDetail as ScanDetailType, HostListResponse, WSMessage } from '../../types';

const STAGE_LABELS = [
  'Ping Sweep',
  'ARP MAC Lookup',
  'Port Scanning',
  'Deep Scan',
];

function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'overview' | 'hosts' | 'logs'>('overview');

  const { data: scan, loading, reload } = useFetch<ScanDetailType>(
    () => scansApi.get(id!),
    [id],
  );

  const { data: hosts } = useFetch<HostListResponse>(
    () => hostsApi.list({ scan_id: id!, page_size: '200' }),
    [id],
  );

  // Poll while scan is running
  const isActive = scan?.status === 'running' || scan?.status === 'pending';
  usePolling(() => reload(), isActive ? 3000 : 0, [isActive]);

  // Real-time updates via WebSocket
  useWebSocket(
    isActive ? `/ws/scans/${id}` : null,
    useCallback((msg: WSMessage) => {
      if (msg.type === 'scan_progress' || msg.type === 'scan_completed' || msg.type === 'scan_failed') {
        reload();
      }
    }, [reload]),
  );

  const handleDelete = async () => {
    if (!confirm('Delete this scan?')) return;
    await scansApi.delete(id!);
    navigate('/scans');
  };

  const handleCancel = async () => {
    await scansApi.cancel(id!);
    reload();
  };

  if (loading && !scan) {
    return <div className="loading-overlay"><div className="spinner" /></div>;
  }
  if (!scan) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">Scan not found</div>
        <button className="btn btn-secondary" onClick={() => navigate('/scans')}>
          <ArrowLeft size={16} /> Back to Scans
        </button>
      </div>
    );
  }

  return (
    <div>
      {/* ── Header ──────────────────────── */}
      <div className="page-header">
        <div className="flex items-center gap-lg">
          <button className="btn btn-ghost btn-icon" onClick={() => navigate('/scans')}>
            <ArrowLeft size={18} />
          </button>
          <div>
            <h1 className="page-title">{scan.name || scan.target}</h1>
            <p className="page-subtitle mono">{scan.target}</p>
          </div>
          <span className={`badge badge-${scan.status}`}>
            <span className="badge-dot" />
            {scan.status}
          </span>
        </div>
        <div className="flex gap-sm">
          {isActive && (
            <button className="btn btn-danger btn-sm" onClick={handleCancel}>
              <XCircle size={14} /> Cancel
            </button>
          )}
          {scan.status === 'completed' && (
            <a href={exportApi.scanUrl(scan.id, 'csv')} download className="btn btn-secondary btn-sm">
              <Download size={14} /> Export
            </a>
          )}
          <button className="btn btn-ghost btn-sm" onClick={handleDelete}>
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* ── Pipeline Stage Indicator ────── */}
      <div className="card mb-xl">
        <div className="flex items-center justify-between mb-lg">
          <span style={{ fontWeight: 600, fontSize: 13 }}>Pipeline Progress</span>
          <span className="text-sm text-muted">
            {scan.stage_label || 'Waiting'}
          </span>
        </div>
        <div className="pipeline-stages">
          {STAGE_LABELS.map((label, i) => {
            const stageNum = i + 1;
            let cls = 'pipeline-stage';
            if (stageNum < scan.current_stage) cls += ' complete';
            else if (stageNum === scan.current_stage && isActive) cls += ' active';
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                {i > 0 && <div className="pipeline-connector" />}
                <div className={cls}>
                  <span style={{ fontWeight: 600, width: 14, textAlign: 'center' }}>{stageNum}</span>
                  {label}
                </div>
              </div>
            );
          })}
        </div>
        <div className="progress-bar mt-lg">
          <div
            className={`progress-bar-fill${scan.status === 'completed' ? ' complete' : ''}`}
            style={{ width: `${(scan.current_stage / scan.total_stages) * 100}%` }}
          />
        </div>
      </div>

      {/* ── Stat Cards ──────────────────── */}
      <div className="stats-grid">
        <MiniStat icon={<Server size={16} />} label="Hosts Found" value={scan.hosts_discovered} color="blue" />
        <MiniStat icon={<Server size={16} />} label="Live Hosts" value={scan.live_hosts} color="green" />
        <MiniStat icon={<Wifi size={16} />} label="Open Ports" value={scan.open_ports_found} color="amber" />
        <MiniStat
          icon={<Clock size={16} />}
          label="Duration"
          value={formatDuration(scan.started_at, scan.completed_at) || '—'}
          color="purple"
          isText
        />
      </div>

      {/* ── Tabs ────────────────────────── */}
      <div className="tab-bar">
        <button className={`tab-btn${activeTab === 'overview' ? ' active' : ''}`} onClick={() => setActiveTab('overview')}>
          Overview
        </button>
        <button className={`tab-btn${activeTab === 'hosts' ? ' active' : ''}`} onClick={() => setActiveTab('hosts')}>
          Hosts ({hosts?.total || 0})
        </button>
        <button className={`tab-btn${activeTab === 'logs' ? ' active' : ''}`} onClick={() => setActiveTab('logs')}>
          Logs ({scan.logs?.length || 0})
        </button>
      </div>

      {/* ── Tab Content ─────────────────── */}
      {activeTab === 'overview' && (
        <div className="detail-grid">
          <DetailItem label="Target" value={scan.target} mono />
          <DetailItem label="Scan Type" value={scan.scan_type.replace('_', ' ')} />
          <DetailItem label="Status" value={scan.status} />
          <DetailItem label="Created" value={formatDate(scan.created_at)} />
          <DetailItem label="Started" value={formatDate(scan.started_at)} />
          <DetailItem label="Completed" value={formatDate(scan.completed_at)} />
          {scan.error_message && (
            <div className="detail-item" style={{ gridColumn: '1 / -1' }}>
              <span className="detail-label">Error</span>
              <span className="detail-value" style={{ color: 'var(--accent-red)' }}>{scan.error_message}</span>
            </div>
          )}
          {scan.description && (
            <div className="detail-item" style={{ gridColumn: '1 / -1' }}>
              <span className="detail-label">Description</span>
              <span className="detail-value">{scan.description}</span>
            </div>
          )}
        </div>
      )}

      {activeTab === 'hosts' && (
        <div className="panel">
          <div className="panel-body no-pad">
            {!hosts || hosts.items.length === 0 ? (
              <div className="empty-state">
                <Server size={40} />
                <div className="empty-state-title">No hosts discovered yet</div>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>MAC</th>
                    <th>Vendor</th>
                    <th>OS</th>
                    <th>Ports</th>
                    <th>Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.items.map((h) => (
                    <tr
                      key={h.id}
                      className="clickable-row"
                      onClick={() => navigate(`/hosts/${h.id}`)}
                    >
                      <td className="mono">{h.ip_address}</td>
                      <td>{h.hostname || '—'}</td>
                      <td className="mono text-sm">{h.mac_address || '—'}</td>
                      <td className="text-sm">{h.vendor || '—'}</td>
                      <td className="text-sm">{h.os_name || '—'}</td>
                      <td>
                        <span className={`badge badge-${h.is_up ? 'open' : 'closed'}`}>
                          {h.is_up ? 'up' : 'down'}
                        </span>
                      </td>
                      <td>
                        <div className="tag-list">
                          {h.tags.map((t) => (
                            <span
                              key={t.id}
                              className="tag-chip"
                              style={{ borderColor: t.color + '40', color: t.color }}
                            >
                              <span className="tag-dot" style={{ background: t.color }} />
                              {t.name}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="log-viewer">
          {(!scan.logs || scan.logs.length === 0) ? (
            <div className="text-muted">No logs yet</div>
          ) : (
            scan.logs.map((log) => (
              <div key={log.id} className="log-entry">
                <span className="log-time">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className={`log-level ${log.level}`}>{log.level}</span>
                <span className="log-message">{log.message}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function MiniStat({ icon, label, value, color, isText }: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  color: string;
  isText?: boolean;
}) {
  return (
    <div className={`card stat-card ${color}`}>
      <div className={`stat-icon ${color}`}>{icon}</div>
      <div className="card-title">{label}</div>
      <div className="card-value" style={isText ? { fontSize: 18 } : {}}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  );
}

function DetailItem({ label, value, mono }: { label: string; value: string | null | undefined; mono?: boolean }) {
  return (
    <div className="detail-item">
      <span className="detail-label">{label}</span>
      <span className={`detail-value${mono ? ' mono' : ''}`}>{value || '—'}</span>
    </div>
  );
}

export default ScanDetail;
