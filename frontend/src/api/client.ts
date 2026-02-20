/* ─── REST API client ────────────────────────── */

import type {
  DashboardStats,
  FirmwareAnalysis,
  FirmwareAnalysisListResponse,
  FirmwareAnalysisSummary,
  FirmwareReport,
  HostDetail,
  HostListResponse,
  HostUpdate,
  Scan,
  ScanCreateRequest,
  ScanDetail,
  ScanListResponse,
  SubnetDetectionResponse,
  Tag,
} from '../types';

const BASE = '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as unknown as T;
  return res.json();
}

/* ── Scans ─────────────────────────────────── */
export const scansApi = {
  list: (params?: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<ScanListResponse>(`/scans${qs ? `?${qs}` : ''}`);
  },
  get: (id: string) => request<ScanDetail>(`/scans/${id}`),
  create: (data: ScanCreateRequest) =>
    request<Scan>('/scans', { method: 'POST', body: JSON.stringify(data) }),
  update: (id: string, data: { name?: string; description?: string }) =>
    request<Scan>(`/scans/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  delete: (id: string) => request<void>(`/scans/${id}`, { method: 'DELETE' }),
  cancel: (id: string) => request<Scan>(`/scans/${id}/cancel`, { method: 'POST' }),
};

/* ── Hosts ─────────────────────────────────── */
export const hostsApi = {
  list: (params?: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<HostListResponse>(`/hosts${qs ? `?${qs}` : ''}`);
  },
  get: (mac: string) => request<HostDetail>(`/hosts/${encodeURIComponent(mac)}`),
  update: (mac: string, data: HostUpdate) =>
    request<HostDetail>(`/hosts/${encodeURIComponent(mac)}`, { method: 'PATCH', body: JSON.stringify(data) }),
  addTag: (mac: string, tagId: string) =>
    request<void>(`/hosts/${encodeURIComponent(mac)}/tags/${tagId}`, { method: 'POST' }),
  removeTag: (mac: string, tagId: string) =>
    request<void>(`/hosts/${encodeURIComponent(mac)}/tags/${tagId}`, { method: 'DELETE' }),
  exportDevices: () => request<{ exported: number; path: string }>('/hosts/export', { method: 'POST' }),
  importDevices: () => request<{ imported: number }>('/hosts/import', { method: 'POST' }),
};

/* ── Tags ──────────────────────────────────── */
export const tagsApi = {
  list: () => request<Tag[]>('/tags'),
  create: (data: { name: string; color: string; description?: string }) =>
    request<Tag>('/tags', { method: 'POST', body: JSON.stringify(data) }),
  delete: (id: string) => request<void>(`/tags/${id}`, { method: 'DELETE' }),
};

/* ── Dashboard ─────────────────────────────── */
export const dashboardApi = {
  stats: () => request<DashboardStats>('/dashboard/stats'),
};

/* ── Network ───────────────────────────────── */
export const networkApi = {
  detectSubnets: () => request<SubnetDetectionResponse>('/network/subnets'),
};

/* ── Export ─────────────────────────────────── */
export const exportApi = {
  scanUrl: (scanId: string, format: 'csv' | 'json' = 'csv') =>
    `${BASE}/export/scans/${scanId}?format=${format}`,
  hostsUrl: (format: 'csv' | 'json' = 'csv') =>
    `${BASE}/export/hosts?format=${format}`,
};

/* ── Firmware Analysis ─────────────────────── */
export const firmwareApi = {
  list: (params?: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<FirmwareAnalysisListResponse>(`/firmware${qs ? `?${qs}` : ''}`);
  },
  get: (id: string) => request<FirmwareAnalysis>(`/firmware/${id}`),
  start: (hostMac: string, fwUrl?: string) =>
    request<FirmwareAnalysis>('/firmware', {
      method: 'POST',
      body: JSON.stringify({ host_mac: hostMac, fw_url: fwUrl }),
    }),
  startBatch: (hostMacs?: string[]) =>
    request<FirmwareAnalysis[]>('/firmware/batch', {
      method: 'POST',
      body: JSON.stringify({ host_macs: hostMacs }),
    }),
  cancel: (id: string) =>
    request<FirmwareAnalysis>(`/firmware/${id}/cancel`, { method: 'POST' }),
  delete: (id: string) =>
    request<void>(`/firmware/${id}`, { method: 'DELETE' }),
  getReport: (id: string) =>
    request<FirmwareReport>(`/firmware/${id}/report`),
  summary: () =>
    request<FirmwareAnalysisSummary>('/firmware/summary'),
};
