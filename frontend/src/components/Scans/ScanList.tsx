import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Radar,
  Plus,
  ChevronLeft,
  ChevronRight,
  Trash2,
  Download,
  X,
} from 'lucide-react';
import { scansApi, exportApi } from '../../api/client';
import { useFetch, usePolling } from '../../hooks/useData';
import { formatRelative, formatDuration } from '../../utils/formatters';
import type { ScanListResponse, ScanType } from '../../types';

function ScanList() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);

  const params: Record<string, string> = { page: String(page), page_size: '20' };
  if (statusFilter) params.status = statusFilter;

  const { data, loading, reload } = useFetch<ScanListResponse>(
    () => scansApi.list(params),
    [page, statusFilter],
  );

  usePolling(reload, 5000);

  const handleCreate = async (target: string, scanType: ScanType, name: string) => {
    setCreating(true);
    try {
      const scan = await scansApi.create({ target, scan_type: scanType, name: name || undefined });
      setShowCreate(false);
      navigate(`/scans/${scan.id}`);
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Failed to create scan');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Delete this scan and all its data?')) return;
    try {
      await scansApi.delete(id);
      reload();
    } catch {
      /* ignore */
    }
  };

  const totalPages = data ? Math.ceil(data.total / data.page_size) : 0;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Network Scans</h1>
          <p className="page-subtitle">Launch and manage discovery scans</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          <Plus size={16} /> New Scan
        </button>
      </div>

      {/* ── Create Panel ────────────────── */}
      {showCreate && (
        <ScanCreateForm
          onSubmit={handleCreate}
          onCancel={() => setShowCreate(false)}
          creating={creating}
        />
      )}

      {/* ── Filters ─────────────────────── */}
      <div className="filter-bar">
        {['', 'pending', 'running', 'completed', 'failed'].map((s) => (
          <button
            key={s}
            className={`filter-chip${statusFilter === s ? ' active' : ''}`}
            onClick={() => { setStatusFilter(s); setPage(1); }}
          >
            {s || 'All'}
          </button>
        ))}
      </div>

      {/* ── Table ───────────────────────── */}
      <div className="panel">
        <div className="panel-body no-pad">
          {loading && !data ? (
            <div className="loading-overlay"><div className="spinner" /></div>
          ) : !data || data.items.length === 0 ? (
            <div className="empty-state">
              <Radar size={48} />
              <div className="empty-state-title">No Scans Found</div>
              <div className="empty-state-text">Launch a new scan to discover your network</div>
            </div>
          ) : (
            <div className="data-table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Name / Target</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Progress</th>
                    <th>Hosts</th>
                    <th>Ports</th>
                    <th>Duration</th>
                    <th>Created</th>
                    <th style={{ width: 80 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((scan) => (
                    <tr
                      key={scan.id}
                      className="clickable-row"
                      onClick={() => navigate(`/scans/${scan.id}`)}
                    >
                      <td>
                        <div style={{ fontWeight: 500 }}>{scan.name || scan.target}</div>
                        {scan.name && (
                          <div className="mono text-muted text-sm">{scan.target}</div>
                        )}
                      </td>
                      <td className="text-sm">{scan.scan_type.replace('_', ' ')}</td>
                      <td>
                        <span className={`badge badge-${scan.status}`}>
                          <span className="badge-dot" />
                          {scan.status}
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-sm">
                          <div className="progress-bar" style={{ width: 60 }}>
                            <div
                              className={`progress-bar-fill${scan.status === 'completed' ? ' complete' : ''}`}
                              style={{ width: `${(scan.current_stage / scan.total_stages) * 100}%` }}
                            />
                          </div>
                          <span className="text-sm text-muted">
                            {scan.current_stage}/{scan.total_stages}
                          </span>
                        </div>
                      </td>
                      <td className="mono">{scan.hosts_discovered}</td>
                      <td className="mono">{scan.open_ports_found}</td>
                      <td className="text-sm text-muted">
                        {formatDuration(scan.started_at, scan.completed_at)}
                      </td>
                      <td className="text-sm text-muted">{formatRelative(scan.created_at)}</td>
                      <td>
                        <div className="flex gap-xs">
                          {scan.status === 'completed' && (
                            <a
                              href={exportApi.scanUrl(scan.id, 'csv')}
                              download
                              className="btn btn-ghost btn-icon btn-sm"
                              title="Export CSV"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <Download size={14} />
                            </a>
                          )}
                          <button
                            className="btn btn-ghost btn-icon btn-sm"
                            title="Delete"
                            onClick={(e) => handleDelete(scan.id, e)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* ── Pagination ──────────────────── */}
      {data && data.total > data.page_size && (
        <div className="pagination">
          <span className="pagination-info">
            Showing {(page - 1) * data.page_size + 1}–{Math.min(page * data.page_size, data.total)} of {data.total}
          </span>
          <div className="pagination-btns">
            <button className="btn btn-secondary btn-sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
              <ChevronLeft size={14} /> Prev
            </button>
            <button className="btn btn-secondary btn-sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Inline scan create form ─────────────────── */
interface CreateFormProps {
  onSubmit: (target: string, scanType: ScanType, name: string) => void;
  onCancel: () => void;
  creating: boolean;
}

function ScanCreateForm({ onSubmit, onCancel, creating }: CreateFormProps) {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState<ScanType>('subnet');
  const [name, setName] = useState('');

  return (
    <div className="scan-launcher">
      <div className="flex items-center justify-between mb-lg">
        <span style={{ fontWeight: 600 }}>Launch New Scan</span>
        <button className="btn btn-ghost btn-icon" onClick={onCancel}>
          <X size={16} />
        </button>
      </div>
      <div className="scan-launcher-form">
        <div className="form-group">
          <label className="form-label">Target</label>
          <input
            className="input input-mono"
            placeholder="192.168.1.0/24 or 10.0.0.1"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>
        <div className="form-group" style={{ maxWidth: 180 }}>
          <label className="form-label">Type</label>
          <select
            className="input select"
            value={scanType}
            onChange={(e) => setScanType(e.target.value as ScanType)}
          >
            <option value="subnet">Subnet</option>
            <option value="single_host">Single Host</option>
            <option value="range">Range</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Name (optional)</label>
          <input
            className="input"
            placeholder="Office network scan"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <button
          className="btn btn-primary"
          disabled={!target.trim() || creating}
          onClick={() => onSubmit(target, scanType, name)}
          style={{ alignSelf: 'flex-end', minWidth: 120 }}
        >
          {creating ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <Radar size={16} />}
          Scan
        </button>
      </div>
    </div>
  );
}

export default ScanList;
