/* ─── TypeScript type definitions ─────────────── */

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanType = 'single_host' | 'subnet' | 'range' | 'custom';

export interface Scan {
  id: string;
  target: string;
  scan_type: ScanType;
  status: ScanStatus;
  name: string | null;
  description: string | null;
  current_stage: number;
  total_stages: number;
  stage_label: string | null;
  hosts_discovered: number;
  live_hosts: number;
  open_ports_found: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface ScanLog {
  id: string;
  stage: number;
  level: string;
  message: string;
  timestamp: string;
}

export interface ScanDetail extends Scan {
  logs: ScanLog[];
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  page: number;
  page_size: number;
}

export interface Host {
  mac_address: string;
  scan_id: string | null;
  ip_address: string;
  hostname: string | null;
  vendor: string | null;
  os_name: string | null;
  os_family: string | null;
  os_accuracy: number | null;
  os_cpe: string | null;
  is_up: boolean;
  response_time_ms: number | null;
  firmware_url: string | null;
  open_port_count: number;
  discovered_at: string;
  last_seen: string;
  tags: Tag[];
}

export interface HostDetail extends Host {
  ports: Port[];
}

export interface HostUpdate {
  hostname?: string | null;
  vendor?: string | null;
  os_name?: string | null;
  os_family?: string | null;
  firmware_url?: string | null;
  ip_address?: string | null;
}

export interface HostListResponse {
  items: Host[];
  total: number;
  page: number;
  page_size: number;
}

export interface Port {
  id: string;
  host_id: string;
  port_number: number;
  protocol: string;
  state: string;
  service_name: string | null;
  service_version: string | null;
  service_product: string | null;
  service_extra_info: string | null;
  service_cpe: string | null;
  scripts_output: string | null;
  banner: string | null;
  discovered_at: string;
}

export interface Tag {
  id: string;
  name: string;
  color: string;
  description?: string | null;
}

export interface DashboardStats {
  scans: {
    total: number;
    running: number;
    completed: number;
    failed: number;
  };
  hosts: {
    total: number;
    live: number;
    unique_ips: number;
  };
  ports: {
    total: number;
    open: number;
  };
  top_services: { name: string; count: number }[];
  top_ports: { port: number; count: number }[];
  os_distribution: { os: string; count: number }[];
  recent_scans: {
    id: string;
    target: string;
    status: string;
    hosts_discovered: number;
    open_ports_found: number;
    created_at: string | null;
    completed_at: string | null;
  }[];
}

export interface ScanCreateRequest {
  target: string;
  scan_type: ScanType;
  name?: string;
  description?: string;
}

export interface SubnetInfo {
  interface: string;
  ip_address: string;
  cidr: string;
  prefix_length: number;
  num_hosts: number;
  is_private: boolean;
}

export interface SubnetDetectionResponse {
  subnets: SubnetInfo[];
  recommended: string | null;
  gateway: string | null;
  all_interfaces: {
    interface: string;
    ip_address: string;
    cidr: string;
    prefix_length: number;
    is_loopback: boolean;
  }[];
}

export interface WSMessage {
  type: string;
  scan_id?: string;
  stage?: number;
  stage_label?: string;
  message?: string;
  data?: Record<string, unknown>;
  error?: string;
  hosts?: number;
  ports?: number;
}
