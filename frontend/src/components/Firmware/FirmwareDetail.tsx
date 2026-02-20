import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Download,
  Cpu,
  Brain,
  CheckCircle,
  XCircle,
  Clock,
  AlertOctagon,
  FileText,
  RefreshCw,
} from 'lucide-react';
import { firmwareApi } from '../../api/client';
import { useFetch } from '../../hooks/useData';
import { formatDate } from '../../utils/formatters';
import type { FirmwareAnalysis, FirmwareReport } from '../../types';

const STAGE_ICONS = [Download, Cpu, Brain];
const STAGE_NAMES = ['Download Firmware', 'EMBA Analysis', 'AI Triage'];

function riskColor(score: number | null): string {
  if (score === null) return 'var(--text-muted)';
  if (score >= 8) return 'var(--accent-red)';
  if (score >= 6) return 'var(--accent-yellow)';
  if (score >= 4) return 'var(--accent-blue)';
  return 'var(--accent-green)';
}

function riskLabel(score: number | null): string {
  if (score === null) return 'N/A';
  if (score >= 8) return 'Critical';
  if (score >= 6) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function FirmwareDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'overview' | 'report'>('overview');
  const [report, setReport] = useState<FirmwareReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);

  const { data: analysis, loading, reload } = useFetch<FirmwareAnalysis>(
    () => firmwareApi.get(id!),
    [id],
  );

  // Auto-refresh while running
  useEffect(() => {
    if (!analysis || ['completed', 'failed', 'cancelled'].includes(analysis.status)) return;
    const interval = setInterval(reload, 3000);
    return () => clearInterval(interval);
  }, [analysis, reload]);

  // Load report when completed and report tab selected
  useEffect(() => {
    if (analysis?.status === 'completed' && activeTab === 'report' && !report) {
      setReportLoading(true);
      firmwareApi.getReport(id!).then(setReport).catch(() => {}).finally(() => setReportLoading(false));
    }
  }, [analysis, activeTab, report, id]);

  if (loading && !analysis) {
    return <div className="loading-overlay"><div className="spinner" /></div>;
  }
  if (!analysis) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">Analysis not found</div>
        <button className="btn btn-secondary" onClick={() => navigate('/firmware')}>
          <ArrowLeft size={16} /> Back
        </button>
      </div>
    );
  }

  const isRunning = !['completed', 'failed', 'cancelled'].includes(analysis.status);

  return (
    <div>
      {/* ── Header ──────────────────────── */}
      <div className="page-header">
        <div className="flex items-center gap-lg">
          <button className="btn btn-ghost btn-icon" onClick={() => navigate('/firmware')}>
            <ArrowLeft size={18} />
          </button>
          <div>
            <h1 className="page-title">
              <Shield size={20} style={{ marginRight: 8 }} />
              Firmware Analysis
            </h1>
            <p className="page-subtitle">
              <span className="mono">{analysis.host_mac}</span>
              {analysis.fw_url && (
                <> &middot; <span className="text-sm">{analysis.fw_url}</span></>
              )}
            </p>
          </div>
        </div>
        <div className="flex gap-sm">
          <button className="btn btn-ghost btn-sm" onClick={reload}>
            <RefreshCw size={14} /> Refresh
          </button>
          {isRunning && (
            <button
              className="btn btn-secondary btn-sm"
              onClick={async () => { await firmwareApi.cancel(id!); reload(); }}
            >
              <XCircle size={14} /> Cancel
            </button>
          )}
        </div>
      </div>

      {/* ── Pipeline Progress ───────────── */}
      <div className="card mb-xl">
        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 16 }}>Pipeline Progress</div>
        <div className="flex gap-xl" style={{ justifyContent: 'space-around' }}>
          {STAGE_NAMES.map((name, i) => {
            const StageIcon = STAGE_ICONS[i];
            const stageNum = i + 1;
            const isActive = analysis.current_stage === stageNum && isRunning;
            const isDone = analysis.current_stage > stageNum || analysis.status === 'completed';
            const isFailed = analysis.status === 'failed' && analysis.current_stage === stageNum;

            let color = 'var(--text-muted)';
            if (isActive) color = 'var(--accent-blue)';
            if (isDone) color = 'var(--accent-green)';
            if (isFailed) color = 'var(--accent-red)';

            return (
              <div key={i} className="flex flex-col items-center gap-sm" style={{ textAlign: 'center' }}>
                <div
                  style={{
                    width: 48,
                    height: 48,
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: `2px solid ${color}`,
                    background: isDone ? color + '20' : 'transparent',
                  }}
                >
                  {isDone ? (
                    <CheckCircle size={22} style={{ color }} />
                  ) : isFailed ? (
                    <AlertOctagon size={22} style={{ color }} />
                  ) : isActive ? (
                    <div className="spinner" style={{ width: 20, height: 20 }} />
                  ) : (
                    <StageIcon size={22} style={{ color }} />
                  )}
                </div>
                <div style={{ fontSize: 12, fontWeight: 600, color }}>{name}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Stage {stageNum}
                </div>
              </div>
            );
          })}
        </div>

        {analysis.stage_label && (
          <div
            style={{
              marginTop: 16,
              padding: '8px 12px',
              background: 'var(--bg-elevated)',
              borderRadius: 6,
              fontSize: 13,
              textAlign: 'center',
            }}
          >
            {isRunning && <Clock size={12} style={{ marginRight: 6, verticalAlign: 'middle' }} />}
            {analysis.stage_label}
          </div>
        )}

        {analysis.error_message && (
          <div
            style={{
              marginTop: 12,
              padding: '8px 12px',
              background: 'rgba(255, 69, 58, 0.1)',
              border: '1px solid rgba(255, 69, 58, 0.3)',
              borderRadius: 6,
              fontSize: 13,
              color: 'var(--accent-red)',
            }}
          >
            <AlertTriangle size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
            {analysis.error_message}
          </div>
        )}
      </div>

      {/* ── Risk Score Card ─────────────── */}
      {analysis.risk_score != null && (
        <div className="card mb-xl">
          <div className="flex items-center justify-between">
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>Risk Score</div>
              <div
                style={{
                  fontSize: 48,
                  fontWeight: 800,
                  color: riskColor(analysis.risk_score),
                  lineHeight: 1,
                }}
              >
                {analysis.risk_score}
                <span style={{ fontSize: 20, fontWeight: 400 }}>/10</span>
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, color: riskColor(analysis.risk_score), marginTop: 4 }}>
                {riskLabel(analysis.risk_score)} Risk
              </div>
            </div>
            <div className="flex gap-xl">
              {analysis.findings_count != null && (
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 24, fontWeight: 700 }}>{analysis.findings_count}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Findings</div>
                </div>
              )}
              {analysis.critical_count != null && (
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-red)' }}>
                    {analysis.critical_count}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Critical</div>
                </div>
              )}
              {analysis.high_count != null && (
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--accent-yellow)' }}>
                    {analysis.high_count}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>High</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Tabs ────────────────────────── */}
      <div className="tab-bar">
        <button
          className={`tab-btn${activeTab === 'overview' ? ' active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Details
        </button>
        <button
          className={`tab-btn${activeTab === 'report' ? ' active' : ''}`}
          onClick={() => setActiveTab('report')}
          disabled={analysis.status !== 'completed'}
        >
          <FileText size={14} style={{ marginRight: 4 }} />
          AI Report
        </button>
      </div>

      {/* ── Overview Tab ────────────────── */}
      {activeTab === 'overview' && (
        <div className="panel">
          <div className="panel-body">
            <div className="detail-grid">
              <DetailItem label="Analysis ID" value={analysis.id} mono />
              <DetailItem label="Host MAC" value={analysis.host_mac} mono />
              <DetailItem label="Status" value={analysis.status} />
              <DetailItem label="Firmware URL" value={analysis.fw_url} mono />
              <DetailItem label="Local Path" value={analysis.fw_path} mono />
              <DetailItem label="SHA-256" value={analysis.fw_hash} mono />
              <DetailItem
                label="File Size"
                value={analysis.fw_size_bytes ? `${(analysis.fw_size_bytes / 1024 / 1024).toFixed(2)} MB` : null}
              />
              <DetailItem label="EMBA Log Dir" value={analysis.emba_log_dir} mono />
              <DetailItem label="Created" value={analysis.created_at ? formatDate(analysis.created_at) : null} />
              <DetailItem label="Started" value={analysis.started_at ? formatDate(analysis.started_at) : null} />
              <DetailItem label="Completed" value={analysis.completed_at ? formatDate(analysis.completed_at) : null} />
            </div>
          </div>
        </div>
      )}

      {/* ── Report Tab ──────────────────── */}
      {activeTab === 'report' && (
        <div className="panel">
          <div className="panel-body">
            {reportLoading ? (
              <div className="loading-overlay"><div className="spinner" /></div>
            ) : report ? (
              <div
                className="markdown-body"
                style={{
                  whiteSpace: 'pre-wrap',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 13,
                  lineHeight: 1.6,
                }}
              >
                {report.report}
              </div>
            ) : (
              <div className="empty-state">
                <FileText size={40} />
                <div className="empty-state-title">No report available</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function DetailItem({ label, value, mono }: { label: string; value: string | null | undefined; mono?: boolean }) {
  return (
    <div className="detail-item">
      <span className="detail-label">{label}</span>
      <span className={`detail-value${mono ? ' mono' : ''}`} style={{ wordBreak: 'break-all' }}>
        {value || '—'}
      </span>
    </div>
  );
}

export default FirmwareDetail;
