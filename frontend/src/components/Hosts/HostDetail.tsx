import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Wifi,
  Tag as TagIcon,
  Plus,
  X,
  Save,
  Edit3,
  Shield,
  Play,
} from 'lucide-react';
import { hostsApi, tagsApi, firmwareApi } from '../../api/client';
import { useFetch } from '../../hooks/useData';
import { formatDate, portLabel } from '../../utils/formatters';
import type { HostDetail as HostDetailType, Tag, HostUpdate, FirmwareAnalysis } from '../../types';

function HostDetail() {
  const { mac } = useParams<{ mac: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'ports' | 'info' | 'tags'>('ports');
  const [allTags, setAllTags] = useState<Tag[]>([]);
  const [showTagPicker, setShowTagPicker] = useState(false);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<string | null>(null);
  const [fwLoading, setFwLoading] = useState(false);
  const [fwAnalyses, setFwAnalyses] = useState<FirmwareAnalysis[]>([]);

  // Editable form fields
  const [form, setForm] = useState<HostUpdate>({});

  const { data: host, loading, reload } = useFetch<HostDetailType>(
    () => hostsApi.get(mac!),
    [mac],
  );

  useEffect(() => {
    tagsApi.list().then(setAllTags).catch(() => {});
  }, []);

  // Load firmware analyses for this host
  useEffect(() => {
    if (mac) {
      firmwareApi.list({ host_mac: mac, page_size: '10' })
        .then(res => setFwAnalyses(res.items))
        .catch(() => {});
    }
  }, [mac]);

  // Sync form state when host data loads or changes
  useEffect(() => {
    if (host) {
      setForm({
        hostname: host.hostname,
        vendor: host.vendor,
        os_name: host.os_name,
        os_family: host.os_family,
        firmware_url: host.firmware_url,
        ip_address: host.ip_address,
      });
    }
  }, [host]);

  const handleSave = async () => {
    if (!mac) return;
    setSaving(true);
    try {
      await hostsApi.update(mac, form);
      setSaveMsg('Saved!');
      setEditing(false);
      reload();
      setTimeout(() => setSaveMsg(null), 3000);
    } catch (e: unknown) {
      setSaveMsg(`Error: ${e instanceof Error ? e.message : 'Unknown'}`);
      setTimeout(() => setSaveMsg(null), 4000);
    } finally {
      setSaving(false);
    }
  };

  const handleAddTag = async (tagId: string) => {
    await hostsApi.addTag(mac!, tagId);
    setShowTagPicker(false);
    reload();
  };

  const handleRemoveTag = async (tagId: string) => {
    await hostsApi.removeTag(mac!, tagId);
    reload();
  };

  const handleStartFirmwareAnalysis = async () => {
    if (!mac || !host?.firmware_url) return;
    setFwLoading(true);
    try {
      const analysis = await firmwareApi.start(mac);
      setFwAnalyses(prev => [analysis, ...prev]);
      navigate(`/firmware/${analysis.id}`);
    } catch (e) {
      alert(`Failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    } finally {
      setFwLoading(false);
    }
  };

  if (loading && !host) {
    return <div className="loading-overlay"><div className="spinner" /></div>;
  }
  if (!host) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">Host not found</div>
        <button className="btn btn-secondary" onClick={() => navigate('/hosts')}>
          <ArrowLeft size={16} /> Back to Hosts
        </button>
      </div>
    );
  }

  const openPorts = host.ports.filter(p => p.state === 'open');
  const untagged = allTags.filter(t => !host.tags.some(ht => ht.id === t.id));

  return (
    <div>
      {/* ── Header ──────────────────────── */}
      <div className="page-header">
        <div className="flex items-center gap-lg">
          <button className="btn btn-ghost btn-icon" onClick={() => navigate('/hosts')}>
            <ArrowLeft size={18} />
          </button>
          <div>
            <h1 className="page-title mono">{host.ip_address}</h1>
            <p className="page-subtitle">{host.hostname || 'No hostname'} &middot; <span className="mono" style={{ fontSize: 12 }}>{host.mac_address}</span></p>
          </div>
          <span className={`badge badge-${host.is_up ? 'open' : 'closed'}`}>
            <span className="badge-dot" />
            {host.is_up ? 'UP' : 'DOWN'}
          </span>
        </div>
        <div className="flex gap-sm items-center">
          {saveMsg && <span style={{ fontSize: 12, color: 'var(--accent-green)' }}>{saveMsg}</span>}
          {editing ? (
            <>
              <button className="btn btn-secondary btn-sm" onClick={() => setEditing(false)}>Cancel</button>
              <button className="btn btn-primary btn-sm" onClick={handleSave} disabled={saving}>
                <Save size={14} /> {saving ? 'Saving...' : 'Save'}
              </button>
            </>
          ) : (
            <button className="btn btn-secondary btn-sm" onClick={() => setEditing(true)}>
              <Edit3 size={14} /> Edit
            </button>
          )}
        </div>
      </div>

      {/* ── Info Grid ───────────────────── */}
      <div className="detail-grid mb-xl">
        <EditableItem label="IP Address" value={form.ip_address} editing={editing} onChange={(v) => setForm({ ...form, ip_address: v })} mono />
        <DetailItem label="MAC Address" value={host.mac_address} mono />
        <EditableItem label="Hostname" value={form.hostname} editing={editing} onChange={(v) => setForm({ ...form, hostname: v })} />
        <EditableItem label="Vendor" value={form.vendor} editing={editing} onChange={(v) => setForm({ ...form, vendor: v })} />
        <EditableItem label="OS" value={form.os_name} editing={editing} onChange={(v) => setForm({ ...form, os_name: v })} />
        <EditableItem label="OS Family" value={form.os_family} editing={editing} onChange={(v) => setForm({ ...form, os_family: v })} />
        <DetailItem label="OS Accuracy" value={host.os_accuracy != null ? `${host.os_accuracy}%` : null} />
        <DetailItem label="Response Time" value={host.response_time_ms != null ? `${host.response_time_ms}ms` : null} />
        <EditableItem label="Firmware URL" value={form.firmware_url} editing={editing} onChange={(v) => setForm({ ...form, firmware_url: v })} mono />
        <DetailItem label="Open Ports" value={String(host.open_port_count)} />
        <DetailItem label="Discovered" value={formatDate(host.discovered_at)} />
        <DetailItem label="Last Seen" value={formatDate(host.last_seen)} />
      </div>

      {/* ── Tags ────────────────────────── */}
      <div className="card mb-xl">
        <div className="flex items-center justify-between mb-lg">
          <div className="flex items-center gap-sm">
            <TagIcon size={16} />
            <span style={{ fontWeight: 600, fontSize: 13 }}>Tags</span>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={() => setShowTagPicker(!showTagPicker)}>
            <Plus size={14} /> Add Tag
          </button>
        </div>

        <div className="tag-list">
          {host.tags.map((t) => (
            <span
              key={t.id}
              className="tag-chip"
              style={{ borderColor: t.color + '40', color: t.color }}
            >
              <span className="tag-dot" style={{ background: t.color }} />
              {t.name}
              <button
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0 }}
                onClick={() => handleRemoveTag(t.id)}
              >
                <X size={12} />
              </button>
            </span>
          ))}
          {host.tags.length === 0 && (
            <span className="text-muted text-sm">No tags assigned</span>
          )}
        </div>

        {showTagPicker && untagged.length > 0 && (
          <div className="mt-lg flex gap-xs" style={{ flexWrap: 'wrap' }}>
            {untagged.map((t) => (
              <button
                key={t.id}
                className="tag-chip"
                style={{ borderColor: t.color + '40', color: t.color, cursor: 'pointer', background: 'none' }}
                onClick={() => handleAddTag(t.id)}
              >
                <Plus size={10} />
                {t.name}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* ── Firmware Analysis ───────────── */}
      <div className="card mb-xl">
        <div className="flex items-center justify-between mb-lg">
          <div className="flex items-center gap-sm">
            <Shield size={16} />
            <span style={{ fontWeight: 600, fontSize: 13 }}>Firmware Analysis</span>
            {host.firmware_status && (
              <span className={`badge badge-${host.firmware_status === 'completed' ? 'open' : host.firmware_status === 'failed' ? 'closed' : 'filtered'}`}>
                {host.firmware_status}
              </span>
            )}
          </div>
          {host.firmware_url && (
            <button
              className="btn btn-primary btn-sm"
              onClick={handleStartFirmwareAnalysis}
              disabled={fwLoading}
            >
              <Play size={14} /> {fwLoading ? 'Starting...' : 'Analyse Firmware'}
            </button>
          )}
        </div>

        {host.risk_score != null && (
          <div className="flex gap-xl mb-lg">
            <div>
              <span className="detail-label">Risk Score</span>
              <span style={{
                fontSize: 24, fontWeight: 800,
                color: host.risk_score >= 8 ? 'var(--accent-red)' : host.risk_score >= 6 ? 'var(--accent-yellow)' : host.risk_score >= 4 ? 'var(--accent-blue)' : 'var(--accent-green)'
              }}>
                {host.risk_score}/10
              </span>
            </div>
          </div>
        )}

        {fwAnalyses.length > 0 ? (
          <div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>Recent Analyses</div>
            {fwAnalyses.slice(0, 3).map((a) => (
              <div
                key={a.id}
                className="flex items-center justify-between"
                style={{
                  padding: '8px 0',
                  borderBottom: '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                }}
                onClick={() => navigate(`/firmware/${a.id}`)}
              >
                <div className="flex items-center gap-sm">
                  <span className={`badge badge-${a.status === 'completed' ? 'open' : a.status === 'failed' ? 'closed' : 'filtered'}`}>
                    {a.status}
                  </span>
                  <span className="text-sm">
                    {a.stage_label || `Stage ${a.current_stage}/${a.total_stages}`}
                  </span>
                </div>
                <div className="flex items-center gap-sm">
                  {a.risk_score != null && (
                    <span style={{
                      fontWeight: 700,
                      color: a.risk_score >= 8 ? 'var(--accent-red)' : a.risk_score >= 6 ? 'var(--accent-yellow)' : 'var(--accent-green)'
                    }}>
                      {a.risk_score}/10
                    </span>
                  )}
                  <span className="text-muted text-sm">{a.created_at ? formatDate(a.created_at) : ''}</span>
                </div>
              </div>
            ))}
          </div>
        ) : !host.firmware_url ? (
          <p className="text-muted text-sm">
            No firmware URL set. Edit this host to add a firmware URL, then analyse it.
          </p>
        ) : (
          <p className="text-muted text-sm">
            No analyses yet. Click "Analyse Firmware" to begin.
          </p>
        )}
      </div>

      {/* ── Tabs ────────────────────────── */}
      <div className="tab-bar">
        <button className={`tab-btn${activeTab === 'ports' ? ' active' : ''}`} onClick={() => setActiveTab('ports')}>
          Ports ({openPorts.length})
        </button>
        <button className={`tab-btn${activeTab === 'info' ? ' active' : ''}`} onClick={() => setActiveTab('info')}>
          All Ports ({host.ports.length})
        </button>
      </div>

      {/* ── Port Table ──────────────────── */}
      {(activeTab === 'ports' || activeTab === 'info') && (
        <div className="panel">
          <div className="panel-body no-pad">
            {host.ports.length === 0 ? (
              <div className="empty-state">
                <Wifi size={40} />
                <div className="empty-state-title">No ports discovered</div>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                    <th>CPE</th>
                    <th>Extra</th>
                  </tr>
                </thead>
                <tbody>
                  {(activeTab === 'ports' ? openPorts : host.ports).map((p) => (
                    <tr key={p.id}>
                      <td className="mono" style={{ fontWeight: 600 }}>
                        {p.port_number}
                        {portLabel(p.port_number) && (
                          <span className="text-muted text-sm" style={{ marginLeft: 6 }}>
                            {portLabel(p.port_number)}
                          </span>
                        )}
                      </td>
                      <td className="text-sm">{p.protocol.toUpperCase()}</td>
                      <td>
                        <span className={`badge badge-${p.state}`}>
                          {p.state}
                        </span>
                      </td>
                      <td>{p.service_name || '—'}</td>
                      <td className="text-sm">{p.service_product || '—'}</td>
                      <td className="mono text-sm">{p.service_version || '—'}</td>
                      <td className="mono text-sm" style={{ maxWidth: 200 }}>
                        <span className="truncate" style={{ display: 'block' }}>
                          {p.service_cpe || '—'}
                        </span>
                      </td>
                      <td className="text-sm">{p.service_extra_info || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Scripts Output ──────────────── */}
      {host.ports.some(p => p.scripts_output) && (
        <div className="panel mt-xl">
          <div className="panel-header">
            <span className="panel-title">Script Output</span>
          </div>
          <div className="panel-body">
            {host.ports
              .filter(p => p.scripts_output)
              .map((p) => (
                <div key={p.id} className="mb-lg">
                  <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>
                    Port {p.port_number}/{p.protocol}
                  </div>
                  <pre
                    className="log-viewer"
                    style={{ whiteSpace: 'pre-wrap', maxHeight: 200 }}
                  >
                    {p.scripts_output}
                  </pre>
                </div>
              ))}
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
      <span className={`detail-value${mono ? ' mono' : ''}`}>{value || '—'}</span>
    </div>
  );
}

function EditableItem({ label, value, editing, onChange, mono }: {
  label: string;
  value: string | null | undefined;
  editing: boolean;
  onChange: (v: string) => void;
  mono?: boolean;
}) {
  if (!editing) {
    return (
      <div className="detail-item">
        <span className="detail-label">{label}</span>
        <span className={`detail-value${mono ? ' mono' : ''}`}>{value || '—'}</span>
      </div>
    );
  }
  return (
    <div className="detail-item">
      <span className="detail-label">{label}</span>
      <input
        className="input"
        style={{ fontSize: 13, padding: '4px 8px' }}
        value={value || ''}
        onChange={(e) => onChange(e.target.value)}
        placeholder={label}
      />
    </div>
  );
}

export default HostDetail;
