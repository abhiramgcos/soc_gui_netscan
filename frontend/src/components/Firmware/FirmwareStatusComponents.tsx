import { AlertTriangle, AlertOctagon } from 'lucide-react';
import type { FirmwareAnalysis } from '../../types';

interface FirmwareStatusBadgeProps {
  analysis: FirmwareAnalysis;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

const STATUS_CONFIG = {
  pending: { bg: '#1f2937', text: '#9ca3af', icon: '⏳', label: 'Pending' },
  downloading: { bg: '#dbeafe', text: '#0369a1', icon: '⬇️', label: 'Downloading' },
  downloaded: { bg: '#dbeafe', text: '#0369a1', icon: '✓', label: 'Downloaded' },
  emba_queued: { bg: '#fef08a', text: '#a16207', icon: '⏳', label: 'EMBA Queued' },
  emba_running: { bg: '#fef08a', text: '#a16207', icon: '⚙️', label: 'EMBA Running' },
  emba_done: { bg: '#fef08a', text: '#a16207', icon: '✓', label: 'EMBA Done' },
  triaging: { bg: '#e9d5ff', text: '#6b21a8', icon: '🧠', label: 'AI Triaging' },
  completed: { bg: '#dcfce7', text: '#166534', icon: '✓', label: 'Completed' },
  failed: { bg: '#fee2e2', text: '#991b1b', icon: '✗', label: 'Failed' },
  cancelled: { bg: '#1f2937', text: '#9ca3af', icon: '◼', label: 'Cancelled' },
};

export function FirmwareStatusBadge({ analysis, showLabel = true, size = 'md' }: FirmwareStatusBadgeProps) {
  const cfg = STATUS_CONFIG[analysis.status];
  
  const sizes = {
    sm: { padding: '4px 8px', fontSize: 12 },
    md: { padding: '6px 12px', fontSize: 14 },
    lg: { padding: '8px 16px', fontSize: 16 },
  };

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        padding: sizes[size].padding,
        fontSize: sizes[size].fontSize,
        backgroundColor: cfg.bg,
        color: cfg.text,
        borderRadius: '6px',
        fontWeight: 500,
      }}
    >
      <span>{cfg.icon}</span>
      {showLabel && <span>{cfg.label}</span>}
    </div>
  );
}

export function FirmwareRiskBadge({ score }: { score: number | null }) {
  if (score === null) {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }

  const level = score >= 8 ? 'Critical' : score >= 6 ? 'High' : score >= 4 ? 'Medium' : 'Low';
  const colors = {
    Critical: { bg: 'rgba(239, 68, 68, 0.1)', text: '#dc2626' },
    High: { bg: 'rgba(245, 158, 11, 0.1)', text: '#d97706' },
    Medium: { bg: 'rgba(59, 130, 246, 0.1)', text: '#2563eb' },
    Low: { bg: 'rgba(16, 185, 129, 0.1)', text: '#059669' },
  };

  const color = colors[level as keyof typeof colors];

  return (
    <div
      style={{
        display: 'inline-flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '6px 12px',
        borderRadius: '6px',
        backgroundColor: color.bg,
        color: color.text,
        fontWeight: 700,
      }}
    >
      <div style={{ fontSize: 18 }}>{score.toFixed(1)}</div>
      <div style={{ fontSize: 11, marginTop: 2 }}>{level}</div>
    </div>
  );
}

export function FirmwareFindingsBadges({
  critical,
  high,
  total,
}: {
  critical: number | null;
  high: number | null;
  total: number | null;
}) {
  return (
    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
      {critical != null && critical > 0 && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            padding: '4px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            color: '#dc2626',
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          <AlertOctagon size={14} />
          <span>{critical} Critical</span>
        </div>
      )}
      {high != null && high > 0 && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            padding: '4px 8px',
            borderRadius: '4px',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            color: '#d97706',
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          <AlertTriangle size={14} />
          <span>{high} High</span>
        </div>
      )}
      {total != null && (
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          {total} findings
        </span>
      )}
      {total == null && (
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>—</span>
      )}
    </div>
  );
}

export function FirmwareProgressBar({ analysis }: { analysis: FirmwareAnalysis }) {
  const progress =
    analysis.total_stages > 0
      ? (analysis.current_stage / analysis.total_stages) * 100
      : 0;

  const isRunning = !['completed', 'failed', 'cancelled'].includes(
    analysis.status,
  );

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: 12,
          color: 'var(--text-muted)',
        }}
      >
        <span>{analysis.stage_label || `Stage ${analysis.current_stage}`}</span>
        <span>
          {analysis.current_stage}/{analysis.total_stages}
        </span>
      </div>
      <div
        style={{
          width: '100%',
          height: 6,
          borderRadius: 3,
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            height: '100%',
            width: `${progress}%`,
            backgroundColor: isRunning ? '#3b82f6' : '#10b981',
            transition: 'width 0.3s ease',
          }}
        />
      </div>
    </div>
  );
}
