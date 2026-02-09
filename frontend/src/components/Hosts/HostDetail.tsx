import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Wifi,
  Tag as TagIcon,
  Plus,
  X,
} from 'lucide-react';
import { hostsApi, tagsApi } from '../../api/client';
import { useFetch } from '../../hooks/useData';
import { formatDate, portLabel } from '../../utils/formatters';
import type { HostDetail as HostDetailType, Tag } from '../../types';

function HostDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'ports' | 'info' | 'tags'>('ports');
  const [allTags, setAllTags] = useState<Tag[]>([]);
  const [showTagPicker, setShowTagPicker] = useState(false);

  const { data: host, loading, reload } = useFetch<HostDetailType>(
    () => hostsApi.get(id!),
    [id],
  );

  useEffect(() => {
    tagsApi.list().then(setAllTags).catch(() => {});
  }, []);

  const handleAddTag = async (tagId: string) => {
    await hostsApi.addTag(id!, tagId);
    setShowTagPicker(false);
    reload();
  };

  const handleRemoveTag = async (tagId: string) => {
    await hostsApi.removeTag(id!, tagId);
    reload();
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
            <p className="page-subtitle">{host.hostname || 'No hostname'}</p>
          </div>
          <span className={`badge badge-${host.is_up ? 'open' : 'closed'}`}>
            <span className="badge-dot" />
            {host.is_up ? 'UP' : 'DOWN'}
          </span>
        </div>
      </div>

      {/* ── Info Grid ───────────────────── */}
      <div className="detail-grid mb-xl">
        <DetailItem label="IP Address" value={host.ip_address} mono />
        <DetailItem label="MAC Address" value={host.mac_address} mono />
        <DetailItem label="Hostname" value={host.hostname} />
        <DetailItem label="Vendor" value={host.vendor} />
        <DetailItem label="OS" value={host.os_name} />
        <DetailItem label="OS Family" value={host.os_family} />
        <DetailItem label="OS Accuracy" value={host.os_accuracy != null ? `${host.os_accuracy}%` : null} />
        <DetailItem label="Response Time" value={host.response_time_ms != null ? `${host.response_time_ms}ms` : null} />
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

export default HostDetail;
