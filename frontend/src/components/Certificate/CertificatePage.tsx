import { useMemo, useState } from 'react';
import { Award, FileDown, ShieldAlert } from 'lucide-react';
import { firmwareApi, hostsApi } from '../../api/client';
import { useFetch } from '../../hooks/useData';
import type {
  FirmwareAnalysis,
  FirmwareAnalysisListResponse,
  Host,
  HostListResponse,
} from '../../types';

interface CertificateData {
  orgName: string;
  generatedAt: string;
  devices: CertificateDevice[];
}

const HOSTS_PAGE_SIZE = 200;

interface CertificateDevice {
  host: Host;
  analysis: FirmwareAnalysis;
}

async function fetchAllHosts(): Promise<HostListResponse> {
  const firstPage = await hostsApi.list({ page: '1', page_size: String(HOSTS_PAGE_SIZE) });
  const totalPages = Math.max(1, Math.ceil(firstPage.total / HOSTS_PAGE_SIZE));

  if (totalPages === 1) return firstPage;

  const requests: Promise<HostListResponse>[] = [];
  for (let page = 2; page <= totalPages; page += 1) {
    requests.push(hostsApi.list({ page: String(page), page_size: String(HOSTS_PAGE_SIZE) }));
  }

  const remainingPages = await Promise.all(requests);
  const allItems = [
    ...firstPage.items,
    ...remainingPages.flatMap((response) => response.items),
  ];

  return {
    items: allItems,
    total: firstPage.total,
    page: 1,
    page_size: allItems.length,
  };
}

async function fetchAllCompletedAnalyses(): Promise<FirmwareAnalysisListResponse> {
  const firstPage = await firmwareApi.list({
    page: '1',
    page_size: String(HOSTS_PAGE_SIZE),
    status: 'completed',
  });
  const totalPages = Math.max(1, Math.ceil(firstPage.total / HOSTS_PAGE_SIZE));

  if (totalPages === 1) return firstPage;

  const requests: Promise<FirmwareAnalysisListResponse>[] = [];
  for (let page = 2; page <= totalPages; page += 1) {
    requests.push(firmwareApi.list({
      page: String(page),
      page_size: String(HOSTS_PAGE_SIZE),
      status: 'completed',
    }));
  }

  const remainingPages = await Promise.all(requests);
  const allItems = [
    ...firstPage.items,
    ...remainingPages.flatMap((response) => response.items),
  ];

  return {
    items: allItems,
    total: firstPage.total,
    page: 1,
    page_size: allItems.length,
  };
}

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

function getAverageRisk(devices: CertificateDevice[]): number | null {
  const withScores = devices.filter((device) => device.analysis.risk_score !== null);
  if (withScores.length === 0) return null;
  const total = withScores.reduce((sum, device) => sum + (device.analysis.risk_score ?? 0), 0);
  return total / withScores.length;
}

function formatHostName(device: Host): string {
  return device.hostname?.trim() || 'Unknown Host';
}

function CertificatePage() {
  const [orgName, setOrgName] = useState('');
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [certificate, setCertificate] = useState<CertificateData | null>(null);

  const hostsReq = useFetch<HostListResponse>(
    () => fetchAllHosts(),
    [],
  );
  const analysesReq = useFetch<FirmwareAnalysisListResponse>(
    () => fetchAllCompletedAnalyses(),
    [],
  );

  const hosts = hostsReq.data?.items ?? [];
  const completedAnalyses = analysesReq.data?.items ?? [];

  const latestCompletedByHost = useMemo(() => {
    const byHost = new Map<string, FirmwareAnalysis>();
    completedAnalyses.forEach((analysis) => {
      const existing = byHost.get(analysis.host_mac);
      if (!existing) {
        byHost.set(analysis.host_mac, analysis);
        return;
      }
      const existingTs = Date.parse(existing.completed_at || existing.created_at);
      const currentTs = Date.parse(analysis.completed_at || analysis.created_at);
      if (currentTs > existingTs) byHost.set(analysis.host_mac, analysis);
    });
    return byHost;
  }, [completedAnalyses]);

  const eligibleHosts = useMemo(
    () => hosts.filter((host) => latestCompletedByHost.has(host.mac_address)),
    [hosts, latestCompletedByHost],
  );

  const selectedDevices = useMemo(() => {
    return eligibleHosts
      .filter((host) => selected[host.mac_address])
      .map((host) => ({
        host,
        analysis: latestCompletedByHost.get(host.mac_address) as FirmwareAnalysis,
      }));
  }, [eligibleHosts, selected, latestCompletedByHost]);

  const allSelected = eligibleHosts.length > 0 && selectedDevices.length === eligibleHosts.length;

  const toggleHost = (macAddress: string) => {
    if (!latestCompletedByHost.has(macAddress)) return;
    setSelected((prev) => ({ ...prev, [macAddress]: !prev[macAddress] }));
  };

  const toggleAllHosts = () => {
    if (allSelected) {
      setSelected({});
      return;
    }

    const nextSelection: Record<string, boolean> = {};
    eligibleHosts.forEach((host) => {
      nextSelection[host.mac_address] = true;
    });
    setSelected(nextSelection);
  };

  const canGenerate = orgName.trim().length > 0 && selectedDevices.length > 0;

  const generateCertificate = () => {
    if (!canGenerate) return;
    setCertificate({
      orgName: orgName.trim(),
      generatedAt: new Date().toISOString(),
      devices: selectedDevices,
    });
  };

  const averageScore = certificate ? getAverageRisk(certificate.devices) : null;
  const averageLevel = getRiskLevel(averageScore);
  const loading = hostsReq.loading || analysesReq.loading;
  const error = hostsReq.error || analysesReq.error;

  return (
    <div className="certificate-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">FIRMAI Certificate Generator</h1>
          <p className="page-subtitle">Generate a FIRMAI security certificate from completed firmware analyses.</p>
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
                {selectedDevices.length} selected / {eligibleHosts.length} eligible ({hosts.length} total)
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
                      <th>Firmware Analysis</th>
                      <th>Risk Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hosts.map((host) => (
                      <tr key={host.mac_address}>
                        <td>
                          {(() => {
                            const analysis = latestCompletedByHost.get(host.mac_address);
                            const selectable = Boolean(analysis);
                            return (
                              <input
                                type="checkbox"
                                checked={!!selected[host.mac_address]}
                                onChange={() => toggleHost(host.mac_address)}
                                aria-label={`Select ${host.mac_address}`}
                                disabled={!selectable}
                                title={!selectable ? 'Requires completed firmware analysis' : 'Selectable'}
                              />
                            );
                          })()}
                        </td>
                        <td className="mono">{host.mac_address}</td>
                        <td className="mono">{host.ip_address}</td>
                        <td>{formatHostName(host)}</td>
                        <td>{host.vendor ?? '-'}</td>
                        <td>
                          {latestCompletedByHost.has(host.mac_address) ? (
                            <span className="badge badge-completed">Completed</span>
                          ) : (
                            <span className="text-muted">Not completed</span>
                          )}
                        </td>
                        <td>
                          {(() => {
                            const analysis = latestCompletedByHost.get(host.mac_address);
                            if (!analysis || analysis.risk_score === null) {
                              return <span className="text-muted">N/A</span>;
                            }
                            return analysis.risk_score.toFixed(2);
                          })()}
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
                  <div className="certificate-doc-kicker">FIRMAI Security Intelligence</div>
                  <h2>Certificate by FIRMAI</h2>
                  <p>
                    This certifies that the following network devices were assessed by the FIRMAI
                    firmware risk workflow and scored for security posture.
                  </p>
                  <div className="certificate-brand-line">
                    <div className="certificate-seal">FIRMAI CERTIFIED</div>
                    <div className="certificate-brand-note">Official Assessment Artifact</div>
                  </div>
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
                        const score = device.analysis.risk_score;
                        const level = getRiskLevel(score);
                        return (
                          <tr key={device.host.mac_address}>
                            <td>{device.host.mac_address}</td>
                            <td>{device.host.ip_address}</td>
                            <td>{formatHostName(device.host)}</td>
                            <td>{score === null ? 'N/A' : score.toFixed(2)}</td>
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
                  <div>Certificate by FIRMAI</div>
                  <div className="certificate-signature">Authorized Digital Issuance - FIRMAI</div>
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
