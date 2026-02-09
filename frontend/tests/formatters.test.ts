/* ─── Unit tests for formatting helpers ────────── */

import { describe, it, expect } from 'vitest';
import { formatDate, formatRelative, formatDuration, truncate, portLabel } from '../src/utils/formatters';

describe('formatDate', () => {
  it('returns — for null', () => {
    expect(formatDate(null)).toBe('—');
  });
  it('formats a valid ISO string', () => {
    const result = formatDate('2024-01-15T10:30:00Z');
    expect(result).toContain('Jan');
    expect(result).toContain('15');
    expect(result).toContain('2024');
  });
});

describe('formatRelative', () => {
  it('returns — for undefined', () => {
    expect(formatRelative(undefined)).toBe('—');
  });
  it('formats a recent timestamp as seconds ago', () => {
    const now = new Date(Date.now() - 5000).toISOString();
    expect(formatRelative(now)).toMatch(/\d+s ago/);
  });
  it('formats an older timestamp as minutes ago', () => {
    const fiveMin = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    expect(formatRelative(fiveMin)).toMatch(/\d+m ago/);
  });
});

describe('formatDuration', () => {
  it('returns — when start is null', () => {
    expect(formatDuration(null, '2024-01-01')).toBe('—');
  });
  it('computes seconds correctly', () => {
    const start = '2024-01-01T00:00:00Z';
    const end = '2024-01-01T00:00:45Z';
    expect(formatDuration(start, end)).toBe('45s');
  });
  it('computes minutes and seconds', () => {
    const start = '2024-01-01T00:00:00Z';
    const end = '2024-01-01T00:03:15Z';
    expect(formatDuration(start, end)).toBe('3m 15s');
  });
});

describe('truncate', () => {
  it('returns — for null', () => {
    expect(truncate(null)).toBe('—');
  });
  it('does not truncate short strings', () => {
    expect(truncate('hello', 10)).toBe('hello');
  });
  it('truncates long strings with ellipsis', () => {
    expect(truncate('a'.repeat(50), 10)).toBe('a'.repeat(10) + '…');
  });
});

describe('portLabel', () => {
  it('returns SSH for port 22', () => {
    expect(portLabel(22)).toBe('SSH');
  });
  it('returns HTTP for port 80', () => {
    expect(portLabel(80)).toBe('HTTP');
  });
  it('returns empty string for unknown port', () => {
    expect(portLabel(99999)).toBe('');
  });
});
