// Cybersecurity DevOps Platform - Type Definitions

export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';

export type Severity = 'info' | 'warning' | 'error' | 'critical';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

export type ComplianceStatus = 'compliant' | 'non-compliant' | 'partial' | 'unknown';

export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

export type AssetType = 'server' | 'workstation' | 'container' | 'cloud' | 'network' | 'database' | 'application';

export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Dashboard Metrics
export interface SecurityMetrics {
  overallScore: number;
  threatLevel: ThreatLevel;
  activeVulnerabilities: number;
  criticalVulnerabilities: number;
  resolvedToday: number;
  complianceScore: number;
  protectedAssets: number;
  openIncidents: number;
}

// Vulnerability
export interface Vulnerability {
  id: string;
  cveId: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  cvss: number;
  affectedAsset: string;
  affectedAssetType: AssetType;
  status: 'open' | 'in-progress' | 'resolved' | 'accepted';
  discoveredAt: Date;
  dueDate?: Date;
  assignee?: string;
  tags: string[];
  exploitsAvailable: boolean;
}

// Threat Intelligence
export interface ThreatIntel {
  id: string;
  name: string;
  type: 'malware' | 'apt' | 'ransomware' | 'phishing' | 'exploit' | 'vulnerability';
  severity: ThreatLevel;
  description: string;
  iocs: string[];
  affectedSystems: string[];
  firstSeen: Date;
  lastSeen: Date;
  activeCampaigns: number;
  references: string[];
}

// Compliance Framework
export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  status: ComplianceStatus;
  overallScore: number;
  controlsTotal: number;
  controlsPassed: number;
  controlsFailed: number;
  controlsInProgress: number;
  lastAuditDate: Date;
  nextAuditDate: Date;
}

export interface ComplianceControl {
  id: string;
  frameworkId: string;
  controlId: string;
  name: string;
  description: string;
  status: ComplianceStatus;
  evidence: string[];
  lastChecked: Date;
}

// Incident
export interface SecurityIncident {
  id: string;
  title: string;
  description: string;
  severity: ThreatLevel;
  status: IncidentStatus;
  type: 'malware' | 'intrusion' | 'data-breach' | 'ddos' | 'phishing' | 'insider' | 'other';
  affectedAssets: string[];
  detectionTime: Date;
  startTime?: Date;
  endTime?: Date;
  assignee?: string;
  team: string[];
  indicators: string[];
  actions: IncidentAction[];
  timeline: IncidentEvent[];
  relatedVulnerabilities: string[];
}

export interface IncidentAction {
  id: string;
  description: string;
  performedBy: string;
  performedAt: Date;
  status: 'completed' | 'pending' | 'in-progress' | 'failed';
}

export interface IncidentEvent {
  timestamp: Date;
  type: 'detection' | 'action' | 'update' | 'escalation' | 'resolution';
  description: string;
  performedBy?: string;
}

// Asset
export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  ipAddress: string;
  macAddress?: string;
  location: string;
  owner: string;
  os?: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  status: 'online' | 'offline' | 'maintenance' | 'compromised';
  lastScan: Date;
  vulnerabilities: number;
  complianceStatus: ComplianceStatus;
  tags: string[];
}

// Security Scan
export interface SecurityScan {
  id: string;
  name: string;
  type: 'vulnerability' | 'compliance' | 'penetration' | 'config' | 'malware';
  status: ScanStatus;
  startedAt: Date;
  completedAt?: Date;
  target: string;
  findings: number;
  criticalFindings: number;
  progress: number;
  initiatedBy: string;
}

// Alert
export interface SecurityAlert {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  timestamp: Date;
  acknowledged: boolean;
  acknowledgedBy?: string;
  acknowledgedAt?: Date;
  asset?: string;
  incidentId?: string;
}

// Dashboard Widget
export interface DashboardWidget {
  id: string;
  type: 'metric' | 'chart' | 'table' | 'list' | 'timeline';
  title: string;
  position: { x: number; y: number };
  size: { width: number; height: number };
  data: unknown;
}

// Constants
export const THREAT_LEVELS: Record<ThreatLevel, { color: string; bgColor: string; label: string }> = {
  low: { color: 'text-green-400', bgColor: 'bg-green-500/20', label: 'Low Risk' },
  medium: { color: 'text-yellow-400', bgColor: 'bg-yellow-500/20', label: 'Medium Risk' },
  high: { color: 'text-orange-400', bgColor: 'bg-orange-500/20', label: 'High Risk' },
  critical: { color: 'text-red-400', bgColor: 'bg-red-500/20', label: 'Critical Risk' },
};

export const VULNERABILITY_COLORS: Record<VulnerabilitySeverity, { color: string; bgColor: string }> = {
  critical: { color: 'text-red-500', bgColor: 'bg-red-500' },
  high: { color: 'text-orange-500', bgColor: 'bg-orange-500' },
  medium: { color: 'text-yellow-500', bgColor: 'bg-yellow-500' },
  low: { color: 'text-blue-500', bgColor: 'bg-blue-500' },
  info: { color: 'text-gray-500', bgColor: 'bg-gray-500' },
};

export const ASSET_ICONS: Record<AssetType, string> = {
  server: '🖥️',
  workstation: '💻',
  container: '📦',
  cloud: '☁️',
  network: '🌐',
  database: '🗄️',
  application: '📱',
};

export const INCIDENT_TYPES = [
  { value: 'malware', label: 'Malware', icon: '🦠' },
  { value: 'intrusion', label: 'Intrusion', icon: '🚫' },
  { value: 'data-breach', label: 'Data Breach', icon: '📤' },
  { value: 'ddos', label: 'DDoS', icon: '🌊' },
  { value: 'phishing', label: 'Phishing', icon: '🎣' },
  { value: 'insider', label: 'Insider Threat', icon: '👤' },
  { value: 'other', label: 'Other', icon: '⚠️' },
];

export const COMPLIANCE_FRAMEWORKS = [
  { id: 'soc2', name: 'SOC 2', description: 'Service Organization Control 2' },
  { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management' },
  { id: 'pci', name: 'PCI DSS', description: 'Payment Card Industry Data Security' },
  { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability and Accountability' },
  { id: 'gdpr', name: 'GDPR', description: 'General Data Protection Regulation' },
  { id: 'nist', name: 'NIST CSF', description: 'Cybersecurity Framework' },
];
