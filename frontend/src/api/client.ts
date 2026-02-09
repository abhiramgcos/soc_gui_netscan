/* ─── REST API client ────────────────────────── */

import type {
  DashboardStats,
  HostDetail,
  HostListResponse,
  Scan,
  ScanCreateRequest,
  ScanDetail,
  ScanListResponse,
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
  get: (id: string) => request<HostDetail>(`/hosts/${id}`),
  addTag: (hostId: string, tagId: string) =>
    request<void>(`/hosts/${hostId}/tags/${tagId}`, { method: 'POST' }),
  removeTag: (hostId: string, tagId: string) =>
    request<void>(`/hosts/${hostId}/tags/${tagId}`, { method: 'DELETE' }),
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

/* ── Export ─────────────────────────────────── */
export const exportApi = {
  scanUrl: (scanId: string, format: 'csv' | 'json' = 'csv') =>
    `${BASE}/export/scans/${scanId}?format=${format}`,
  hostsUrl: (format: 'csv' | 'json' = 'csv') =>
    `${BASE}/export/hosts?format=${format}`,
};
