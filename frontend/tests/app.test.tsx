/* ─── Component render tests ──────────────────── */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import App from '../src/App';
import type { DashboardStats } from '../src/types';

function mockFetchResponse(data: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
  });
}

const emptyDashboard: DashboardStats = {
  scans: { total: 0, running: 0, completed: 0, failed: 0 },
  hosts: { total: 0, live: 0, unique_ips: 0 },
  ports: { total: 0, open: 0 },
  top_services: [],
  top_ports: [],
  os_distribution: [],
  recent_scans: [],
};

describe('App', () => {
  beforeEach(() => {
    (global.fetch as ReturnType<typeof vi.fn>).mockReset();
  });

  it('renders dashboard route by default', async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockImplementation(
      mockFetchResponse(emptyDashboard),
    );

    render(
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>,
    );

    expect(screen.getByText(/dashboard/i)).toBeTruthy();
  });

  it('renders scans route', async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockImplementation(
      mockFetchResponse({ items: [], total: 0, page: 1, page_size: 20 }),
    );

    render(
      <MemoryRouter initialEntries={['/scans']}>
        <App />
      </MemoryRouter>,
    );

    expect(screen.getByText(/scans/i)).toBeTruthy();
  });

  it('renders hosts route', async () => {
    (global.fetch as ReturnType<typeof vi.fn>).mockImplementation(
      mockFetchResponse({ items: [], total: 0, page: 1, page_size: 50 }),
    );

    render(
      <MemoryRouter initialEntries={['/hosts']}>
        <App />
      </MemoryRouter>,
    );

    expect(screen.getByText(/hosts/i)).toBeTruthy();
  });
});
