import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Server,
  Search,
  ChevronLeft,
  ChevronRight,
  Download,
  Upload,
  Save,
  X,
} from 'lucide-react';
import { hostsApi, exportApi } from '../../api/client';
import { useFetch, usePolling } from '../../hooks/useData';
import { formatRelative } from '../../utils/formatters';
import type { HostListResponse } from '../../types';

function HostTable() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const [upFilter, setUpFilter] = useState<string>('');
  const [exportMsg, setExportMsg] = useState<string | null>(null);

  const params: Record<string, string> = { page: String(page), page_size: '50' };
  if (search) params.search = search;
  if (osFilter) params.os_family = osFilter;
  if (upFilter === 'up') params.is_up = 'true';
  if (upFilter === 'down') params.is_up = 'false';

  const { data, loading, reload } = useFetch<HostListResponse>(
    () => hostsApi.list(params),
    [page, search, osFilter, upFilter],
  );

  usePolling(reload, 10000);

  const handleExportDevices = async () => {
    try {
      const res = await hostsApi.exportDevices();
      setExportMsg(`Exported ${res.exported} devices to db/devices/`);
      setTimeout(() => setExportMsg(null), 4000);
    } catch (e: unknown) {
      setExportMsg(`Export failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
      setTimeout(() => setExportMsg(null), 4000);
    }
  };

  const handleImportDevices = async () => {
    try {
      const res = await hostsApi.importDevices();
      setExportMsg(`Imported ${res.imported} devices from db/devices/`);
      reload();
      setTimeout(() => setExportMsg(null), 4000);
    } catch (e: unknown) {
      setExportMsg(`Import failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
      setTimeout(() => setExportMsg(null), 4000);
    }
  };

  const totalPages = data ? Math.ceil(data.total / data.page_size) : 0;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Device Inventory</h1>
          <p className="page-subtitle">
            {data ? `${data.total} devices` : 'Loading...'}
            {exportMsg && <span style={{ marginLeft: 12, color: 'var(--accent-green)' }}>{exportMsg}</span>}
          </p>
        </div>
        <div className="flex gap-sm">
          <button className="btn btn-secondary btn-sm" onClick={handleImportDevices}>
            <Upload size={14} /> Import Device DB
          </button>
          <button className="btn btn-secondary btn-sm" onClick={handleExportDevices}>
            <Save size={14} /> Save Device DB
          </button>
          <a href={exportApi.hostsUrl('csv')} download className="btn btn-secondary btn-sm">
            <Download size={14} /> CSV
          </a>
          <a href={exportApi.hostsUrl('json')} download className="btn btn-secondary btn-sm">
            <Download size={14} /> JSON
          </a>
        </div>
      </div>

      {/* ── Search & Filters ────────────── */}
      <div className="filter-bar">
        <div className="search-input-wrap" style={{ maxWidth: 300 }}>
          <Search />
          <input
            className="input"
            placeholder="Search IP, hostname, OS, vendor..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            style={{ paddingLeft: 34 }}
          />
        </div>
        <select
          className="input select"
          style={{ maxWidth: 160 }}
          value={osFilter}
          onChange={(e) => { setOsFilter(e.target.value); setPage(1); }}
        >
          <option value="">All OS</option>
          <option value="Linux">Linux</option>
          <option value="Windows">Windows</option>
          <option value="macOS">macOS</option>
          <option value="IOS">Cisco IOS</option>
          <option value="Embedded">Embedded</option>
        </select>
        <div className="flex gap-xs">
          {['', 'up', 'down'].map((v) => (
            <button
              key={v}
              className={`filter-chip${upFilter === v ? ' active' : ''}`}
              onClick={() => { setUpFilter(v); setPage(1); }}
            >
              {v || 'All'}
            </button>
          ))}
        </div>
        {(search || osFilter || upFilter) && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => { setSearch(''); setOsFilter(''); setUpFilter(''); setPage(1); }}
          >
            <X size={14} /> Clear
          </button>
        )}
      </div>

      {/* ── Table ───────────────────────── */}
      <div className="panel">
        <div className="panel-body no-pad">
          {loading && !data ? (
            <div className="loading-overlay"><div className="spinner" /></div>
          ) : !data || data.items.length === 0 ? (
            <div className="empty-state">
              <Server size={48} />
              <div className="empty-state-title">No Hosts Found</div>
              <div className="empty-state-text">
                {search ? 'No results match your search' : 'Run a scan to discover hosts'}
              </div>
            </div>
          ) : (
            <div className="data-table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>MAC Address</th>
                    <th>Vendor</th>
                    <th>Operating System</th>
                    <th>Ports</th>
                    <th>Firmware URL</th>
                    <th>Tags</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((host) => (
                    <tr
                      key={host.mac_address}
                      className="clickable-row"
                      onClick={() => navigate(`/hosts/${encodeURIComponent(host.mac_address)}`)}
                    >
                      <td>
                        <span className={`badge badge-${host.is_up ? 'open' : 'closed'}`}>
                          <span className="badge-dot" />
                          {host.is_up ? 'UP' : 'DOWN'}
                        </span>
                      </td>
                      <td className="mono">{host.ip_address}</td>
                      <td>{host.hostname || '—'}</td>
                      <td className="mono text-sm">{host.mac_address || '—'}</td>
                      <td className="text-sm">{host.vendor || '—'}</td>
                      <td className="text-sm">
                        <div>{host.os_name || '—'}</div>
                        {host.os_family && (
                          <div className="text-muted" style={{ fontSize: 11 }}>{host.os_family}</div>
                        )}
                      </td>
                      <td>
                        <span className="mono text-sm">{host.open_port_count}</span>
                      </td>
                      <td className="text-sm" style={{ maxWidth: 180 }}>
                        {host.firmware_url ? (
                          <a
                            href={host.firmware_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="truncate"
                            style={{ display: 'block', color: 'var(--accent-blue)' }}
                            onClick={(e) => e.stopPropagation()}
                          >
                            {host.firmware_url}
                          </a>
                        ) : '—'}
                      </td>
                      <td>
                        <div className="tag-list">
                          {host.tags.map((t) => (
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
                      <td className="text-sm text-muted">{formatRelative(host.last_seen)}</td>
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

export default HostTable;
