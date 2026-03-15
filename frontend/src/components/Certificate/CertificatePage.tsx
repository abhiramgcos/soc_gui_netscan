import { useMemo, useState } from 'react';
import { Award, FileDown, ShieldAlert } from 'lucide-react';
import { hostsApi } from '../../api/client';
import { useFetch } from '../../hooks/useData';
import type { Host, HostListResponse } from '../../types';

interface CertificateData {
  orgName: string;
  generatedAt: string;
  devices: Host[];
}

const MAX_HOSTS = 500;

function getRiskLevel(score: number | null): 'low' | 'medium' | 'high' | 'critical' | 'na' {
  if (score === null) return 'na';
  if (score < 3) return 'low';
  if (score < 6) return 'medium';
  if (score < 8) return 'high';
  return 'critical';
}

function getRiskLabel(level: ReturnType<typeof getRiskLevel>): string {
  if (level === 'low') return 'Low';
  if (level === 'medium') return 'Medium';
  if (level === 'high') return 'High';
  if (level === 'critical') return 'Critical';
  return 'Not Analyzed';
}

function getAverageRisk(devices: Host[]): number | null {
  const withScores = devices.filter((device) => device.risk_score !== null);
  if (withScores.length === 0) return null;
  const total = withScores.reduce((sum, device) => sum + (device.risk_score ?? 0), 0);
  return total / withScores.length;
}

function formatHostName(device: Host): string {
  return device.hostname?.trim() || 'Unknown Host';
}

function CertificatePage() {
  const [orgName, setOrgName] = useState('');
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [certificate, setCertificate] = useState<CertificateData | null>(null);

  const { data, loading, error } = useFetch<HostListResponse>(
    () => hostsApi.list({ page: '1', page_size: String(MAX_HOSTS) }),
    [],
  );

  const hosts = data?.items ?? [];

  const selectedHosts = useMemo(
    () => hosts.filter((host) => selected[host.mac_address]),
    [hosts, selected],
  );

  const allSelected = hosts.length > 0 && selectedHosts.length === hosts.length;

  const toggleHost = (macAddress: string) => {
    setSelected((prev) => ({ ...prev, [macAddress]: !prev[macAddress] }));
  };

  const toggleAllHosts = () => {
    if (allSelected) {
      setSelected({});
      return;
    }

    const nextSelection: Record<string, boolean> = {};
    hosts.forEach((host) => {
      nextSelection[host.mac_address] = true;
    });
    setSelected(nextSelection);
  };

  const canGenerate = orgName.trim().length > 0 && selectedHosts.length > 0;

  const generateCertificate = () => {
    if (!canGenerate) return;
    setCertificate({
      orgName: orgName.trim(),
      generatedAt: new Date().toISOString(),
      devices: selectedHosts,
    });
  };

  const averageScore = certificate ? getAverageRisk(certificate.devices) : null;
  const averageLevel = getRiskLevel(averageScore);

  return (
    <div className="certificate-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Certificate Generator</h1>
          <p className="page-subtitle">Generate a printable certificate from selected device risk scores.</p>
        </div>
      </div>

      <div className="certificate-wrapper">
        <section className="panel certificate-config no-print">
          <div className="panel-header">
            <div className="panel-title">Certificate Settings</div>
          </div>
          <div className="panel-body">
            <div className="form-group mb-lg">
              <label htmlFor="org-name" className="form-label">Organization Name</label>
              <input
                id="org-name"
                className="input"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Enter organization name"
              />
            </div>

            <div className="section-header" style={{ marginBottom: 10 }}>
              <div className="section-title">Select Devices</div>
              <div className="text-sm text-muted">
                {selectedHosts.length} selected / {hosts.length}
              </div>
            </div>

            {loading && (
              <div className="loading-overlay">
                <div className="spinner" />
              </div>
            )}

            {error && !loading && (
              <div className="empty-state" style={{ padding: 20 }}>
                <ShieldAlert />
                <div className="empty-state-title">Unable to load devices</div>
                <div className="empty-state-text">{error}</div>
              </div>
            )}

            {!loading && !error && (
              <div className="data-table-wrap certificate-table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: 40 }}>
                        <input
                          type="checkbox"
                          checked={allSelected}
                          onChange={toggleAllHosts}
                          aria-label="Select all devices"
                        />
                      </th>
                      <th>MAC Address</th>
                      <th>IP Address</th>
                      <th>Hostname</th>
                      <th>Vendor</th>
                      <th>Risk Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hosts.map((host) => (
                      <tr key={host.mac_address}>
                        <td>
                          <input
                            type="checkbox"
                            checked={!!selected[host.mac_address]}
                            onChange={() => toggleHost(host.mac_address)}
                            aria-label={`Select ${host.mac_address}`}
                          />
                        </td>
                        <td className="mono">{host.mac_address}</td>
                        <td className="mono">{host.ip_address}</td>
                        <td>{formatHostName(host)}</td>
                        <td>{host.vendor ?? '-'}</td>
                        <td>
                          {host.risk_score === null ? (
                            <span className="text-muted">N/A</span>
                          ) : (
                            host.risk_score.toFixed(2)
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div className="certificate-actions">
              <button
                type="button"
                className="btn btn-primary"
                onClick={generateCertificate}
                disabled={!canGenerate}
              >
                <Award size={16} /> Generate Certificate
              </button>
            </div>
          </div>
        </section>

        <section className="certificate-preview">
          {!certificate && (
            <div className="panel certificate-placeholder">
              <div className="empty-state" style={{ minHeight: 420 }}>
                <Award />
                <div className="empty-state-title">Certificate Preview</div>
                <div className="empty-state-text">
                  Enter an organization name and select at least one device to generate the certificate.
                </div>
              </div>
            </div>
          )}

          {certificate && (
            <>
              <div className="no-print certificate-print-actions">
                <button type="button" className="btn btn-secondary" onClick={() => window.print()}>
                  <FileDown size={16} /> Print / Download PDF
                </button>
              </div>

              <article className="certificate-doc">
                <div className="certificate-doc-header">
                  <div className="certificate-doc-kicker">NetRecon Security Program</div>
                  <h2>Security Assessment Certificate</h2>
                  <p>This certifies that the following network devices were evaluated for firmware security posture.</p>
                </div>

                <div className="certificate-doc-meta">
                  <div>
                    <div className="certificate-label">Issued To</div>
                    <div className="certificate-value">{certificate.orgName}</div>
                  </div>
                  <div>
                    <div className="certificate-label">Issue Date</div>
                    <div className="certificate-value">{new Date(certificate.generatedAt).toLocaleDateString()}</div>
                  </div>
                  <div>
                    <div className="certificate-label">Devices Assessed</div>
                    <div className="certificate-value">{certificate.devices.length}</div>
                  </div>
                  <div>
                    <div className="certificate-label">Overall Risk Score</div>
                    <div className="certificate-value">
                      {averageScore === null ? 'N/A' : averageScore.toFixed(2)}
                      <span className={`certificate-risk risk-${averageLevel}`}>{getRiskLabel(averageLevel)}</span>
                    </div>
                  </div>
                </div>

                <div className="certificate-doc-table-wrap">
                  <table className="certificate-doc-table">
                    <thead>
                      <tr>
                        <th>MAC Address</th>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                      </tr>
                    </thead>
                    <tbody>
                      {certificate.devices.map((device) => {
                        const level = getRiskLevel(device.risk_score);
                        return (
                          <tr key={device.mac_address}>
                            <td>{device.mac_address}</td>
                            <td>{device.ip_address}</td>
                            <td>{formatHostName(device)}</td>
                            <td>{device.risk_score === null ? 'N/A' : device.risk_score.toFixed(2)}</td>
                            <td>
                              <span className={`certificate-risk risk-${level}`}>{getRiskLabel(level)}</span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                <div className="certificate-doc-footer">
                  <div>Issued by NetRecon Security Platform</div>
                  <div className="certificate-signature">Authorized Digital Issuance</div>
                </div>
              </article>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

export default CertificatePage;
