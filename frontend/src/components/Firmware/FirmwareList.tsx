import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Play,
  XCircle,
  Trash2,
  RefreshCw,
  Download,
  Cpu,
  Brain,
  CheckCircle,
  Clock,
  AlertOctagon,
} from 'lucide-react';
import { firmwareApi } from '../../api/client';
import { useFetch } from '../../hooks/useData';
import { formatDate } from '../../utils/formatters';
import type { FirmwareAnalysis, FirmwareAnalysisSummary } from '../../types';

const STATUS_CONFIG: Record<string, { color: string; icon: typeof Shield; label: string }> = {
  pending:      { color: 'var(--text-muted)',   icon: Clock,         label: 'Pending' },
  downloading:  { color: 'var(--accent-blue)',   icon: Download,      label: 'Downloading' },
  downloaded:   { color: 'var(--accent-blue)',   icon: Download,      label: 'Downloaded' },
  emba_queued:  { color: 'var(--accent-yellow)', icon: Clock,         label: 'EMBA Queued' },
  emba_running: { color: 'var(--accent-yellow)', icon: Cpu,           label: 'EMBA Running' },
  emba_done:    { color: 'var(--accent-yellow)', icon: Cpu,           label: 'EMBA Done' },
  triaging:     { color: 'var(--accent-purple)', icon: Brain,         label: 'AI Triaging' },
  completed:    { color: 'var(--accent-green)',  icon: CheckCircle,   label: 'Completed' },
  failed:       { color: 'var(--accent-red)',    icon: AlertOctagon,  label: 'Failed' },
  cancelled:    { color: 'var(--text-muted)',    icon: XCircle,       label: 'Cancelled' },
};

function riskColor(score: number | null): string {
  if (score === null) return 'var(--text-muted)';
  if (score >= 8) return 'var(--accent-red)';
  if (score >= 6) return 'var(--accent-yellow)';
  if (score >= 4) return 'var(--accent-blue)';
  return 'var(--accent-green)';
}

function FirmwareList() {
  const navigate = useNavigate();
  const [batchLoading, setBatchLoading] = useState(false);

  const { data: analyses, loading, reload } = useFetch<{ items: FirmwareAnalysis[]; total: number }>(
    () => firmwareApi.list({ page_size: '100' }),
    [],
  );

  const { data: summary, reload: reloadSummary } = useFetch<FirmwareAnalysisSummary>(
    () => firmwareApi.summary(),
    [],
  );

  // Auto-refresh while there are running analyses
  useEffect(() => {
    const hasRunning = analyses?.items.some((a: FirmwareAnalysis) =>
      !['completed', 'failed', 'cancelled'].includes(a.status)
    );
    if (!hasRunning) return;

    const interval = setInterval(() => {
      reload();
      reloadSummary();
    }, 5000);
    return () => clearInterval(interval);
  }, [analyses, reload, reloadSummary]);

  const handleBatchStart = async () => {
    setBatchLoading(true);
    try {
      await firmwareApi.startBatch();
      reload();
      reloadSummary();
    } catch (e) {
      alert(`Failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    } finally {
      setBatchLoading(false);
    }
  };

  const handleCancel = async (id: string) => {
    try {
      await firmwareApi.cancel(id);
      reload();
    } catch (e) {
      alert(`Failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await firmwareApi.delete(id);
      reload();
      reloadSummary();
    } catch (e) {
      alert(`Failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  return (
    <div>
      {/* ── Header ──────────────────────── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Shield size={22} style={{ marginRight: 8 }} />
            Firmware Analysis
          </h1>
          <p className="page-subtitle">
            Download, EMBA scan, and AI triage firmware for discovered devices
          </p>
        </div>
        <div className="flex gap-sm">
          <button className="btn btn-ghost btn-sm" onClick={() => { reload(); reloadSummary(); }}>
            <RefreshCw size={14} /> Refresh
          </button>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleBatchStart}
            disabled={batchLoading}
          >
            <Play size={14} /> {batchLoading ? 'Starting...' : 'Analyse All'}
          </button>
        </div>
      </div>

      {/* ── Summary Cards ───────────────── */}
      {summary && (
        <div className="stats-grid mb-xl">
          <div className="stat-card">
            <div className="stat-label">Total Analyses</div>
            <div className="stat-value">{summary.total}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Running</div>
            <div className="stat-value" style={{ color: 'var(--accent-yellow)' }}>
              {summary.running + summary.pending}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Completed</div>
            <div className="stat-value" style={{ color: 'var(--accent-green)' }}>
              {summary.completed}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Failed</div>
            <div className="stat-value" style={{ color: 'var(--accent-red)' }}>
              {summary.failed}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Avg Risk Score</div>
            <div className="stat-value" style={{ color: riskColor(summary.avg_risk_score) }}>
              {summary.avg_risk_score != null ? `${summary.avg_risk_score}/10` : '—'}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Critical Findings</div>
            <div className="stat-value" style={{ color: 'var(--accent-red)' }}>
              {summary.total_critical}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">High Findings</div>
            <div className="stat-value" style={{ color: 'var(--accent-yellow)' }}>
              {summary.total_high}
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Hosts w/ FW URL</div>
            <div className="stat-value">{summary.hosts_with_firmware_url}</div>
          </div>
        </div>
      )}

      {/* ── Analysis Table ──────────────── */}
      {loading && !analyses ? (
        <div className="loading-overlay"><div className="spinner" /></div>
      ) : (
        <div className="panel">
          <div className="panel-body no-pad">
            {!analyses?.items.length ? (
              <div className="empty-state">
                <Shield size={40} />
                <div className="empty-state-title">No firmware analyses</div>
                <p className="text-muted text-sm">
                  Set firmware URLs on hosts, then click "Analyse All" to begin.
                </p>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Host</th>
                    <th>Status</th>
                    <th>Stage</th>
                    <th>Risk Score</th>
                    <th>Findings</th>
                    <th>Started</th>
                    <th>Completed</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {analyses.items.map((a) => {
                    const cfg = STATUS_CONFIG[a.status] || STATUS_CONFIG.pending;
                    const Icon = cfg.icon;
                    return (
                      <tr key={a.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/firmware/${a.id}`)}>
                        <td>
                          <div>
                            <span className="mono" style={{ fontWeight: 600 }}>{a.host_mac}</span>
                          </div>
                          {a.fw_url && (
                            <span className="text-muted text-sm truncate" style={{ maxWidth: 200, display: 'block' }}>
                              {a.fw_url}
                            </span>
                          )}
                        </td>
                        <td>
                          <span className="flex items-center gap-xs" style={{ color: cfg.color }}>
                            <Icon size={14} />
                            {cfg.label}
                          </span>
                        </td>
                        <td>
                          <span className="text-sm">
                            {a.stage_label || `${a.current_stage}/${a.total_stages}`}
                          </span>
                          <div
                            className="progress-bar"
                            style={{ width: 60, height: 4, marginTop: 4 }}
                          >
                            <div
                              className="progress-fill"
                              style={{
                                width: `${(a.current_stage / a.total_stages) * 100}%`,
                                background: cfg.color,
                              }}
                            />
                          </div>
                        </td>
                        <td>
                          {a.risk_score != null ? (
                            <span
                              style={{
                                fontWeight: 700,
                                fontSize: 16,
                                color: riskColor(a.risk_score),
                              }}
                            >
                              {a.risk_score}/10
                            </span>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                        <td>
                          <div className="flex gap-xs items-center">
                            {a.critical_count != null && a.critical_count > 0 && (
                              <span className="badge badge-closed" title="Critical">
                                {a.critical_count}C
                              </span>
                            )}
                            {a.high_count != null && a.high_count > 0 && (
                              <span className="badge badge-filtered" title="High">
                                {a.high_count}H
                              </span>
                            )}
                            {a.findings_count != null && (
                              <span className="text-sm text-muted">
                                {a.findings_count} total
                              </span>
                            )}
                            {a.findings_count == null && (
                              <span className="text-muted">—</span>
                            )}
                          </div>
                        </td>
                        <td className="text-sm">{a.started_at ? formatDate(a.started_at) : '—'}</td>
                        <td className="text-sm">{a.completed_at ? formatDate(a.completed_at) : '—'}</td>
                        <td>
                          <div className="flex gap-xs" onClick={(e) => e.stopPropagation()}>
                            {!['completed', 'failed', 'cancelled'].includes(a.status) && (
                              <button
                                className="btn btn-ghost btn-icon btn-sm"
                                title="Cancel"
                                onClick={() => handleCancel(a.id)}
                              >
                                <XCircle size={14} />
                              </button>
                            )}
                            {['completed', 'failed', 'cancelled'].includes(a.status) && (
                              <button
                                className="btn btn-ghost btn-icon btn-sm"
                                title="Delete"
                                onClick={() => handleDelete(a.id)}
                              >
                                <Trash2 size={14} />
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default FirmwareList;
