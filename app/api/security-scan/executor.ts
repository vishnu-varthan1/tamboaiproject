// =====================================================
// AI-POWERED SECURITY SCAN ENGINE
// Simulates Tambo AI API for real-time security scanning
// =====================================================

// =====================================================
// SCAN CONFIGURATION
// =====================================================

interface ScanConfig {
  scanType: 'vulnerability' | 'compliance' | 'full';
  target: string;
  options: {
    includeCVE: boolean;
    includeMITRE: boolean;
    includeCompliance: boolean;
    includeThreatIntel: boolean;
  };
  timeRange: '24h' | '7d' | '30d' | '90d';
}

// =====================================================
// VULNERABILITY DATABASE
// =====================================================

interface Vulnerability {
  id: string;
  cveId?: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss: number;
  cvssVector: string;
  affectedAsset: string;
  affectedComponent: string;
  port?: number;
  service?: string;
  discoveredAt: Date;
  status: 'open' | 'in_progress' | 'resolved';
  exploitAvailable: boolean;
  exploitInWild: boolean;
  cisaKev: boolean;
  patchAvailable: boolean;
  patchId?: string;
  mitreTechniques: string[];
  threatIntel?: {
    aptGroup?: string;
    malwareFamily?: string;
    iocs: string[];
  };
  remediation: string;
  timeline: {
    discovered: Date;
    reported: Date;
    lastUpdated: Date;
  };
}

interface VulnerabilityItem {
  id: string;
  type?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description?: string;
  cvss?: number;
  cve?: string;
  affectedComponent?: string;
  remediation?: string;
  confidence?: number;
}

const vulnerabilityDatabase: Vulnerability[] = [
  {
    id: 'VULN-001',
    cveId: 'CVE-2024-3400',
    title: 'Command Injection in Next.js Route Handler',
    description: 'A critical command injection vulnerability exists in Next.js route handler processing, allowing unauthenticated remote attackers to execute arbitrary commands through specially crafted HTTP requests.',
    severity: 'critical',
    cvss: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    affectedAsset: 'app-server-01 (10.0.1.25)',
    affectedComponent: 'app/api/chat/route.ts',
    port: 443,
    service: 'Next.js',
    discoveredAt: new Date('2026-02-07T04:00:00Z'),
    status: 'open',
    exploitAvailable: true,
    exploitInWild: true,
    cisaKev: true,
    patchAvailable: true,
    patchId: 'Next.js 14.2.0',
    mitreTechniques: ['T1190', 'T1059', 'T1566'],
    threatIntel: {
      aptGroup: 'APT28',
      malwareFamily: 'Drovorub',
      iocs: ['91.207.174.23', 'malware.payload.com'],
    },
    remediation: 'Upgrade Next.js to version 14.2.0 or later immediately. Deploy WAF rules blocking exploitation patterns as interim mitigation.',
    timeline: {
      discovered: new Date('2026-02-07T04:00:00Z'),
      reported: new Date('2026-02-07T04:05:00Z'),
      lastUpdated: new Date('2026-02-07T07:30:00Z'),
    },
  },
  {
    id: 'VULN-002',
    cveId: undefined,
    title: 'Open Redirect in OAuth Callback Handler',
    description: 'Open redirect vulnerability in OAuth callback handler allows attackers to redirect victims to malicious sites, enabling phishing campaigns with legitimate-looking URLs.',
    severity: 'high',
    cvss: 7.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N',
    affectedAsset: 'auth-service (10.0.1.35)',
    affectedComponent: 'app/auth/callback/route.ts',
    discoveredAt: new Date('2026-02-07T04:00:00Z'),
    status: 'open',
    exploitAvailable: true,
    exploitInWild: false,
    cisaKev: false,
    patchAvailable: false,
    mitreTechniques: ['T1566'],
    threatIntel: {
      iocs: ['evil.example.com'],
    },
    remediation: 'Implement strict redirect URL validation whitelist. Validate all redirect URLs against approved list server-side before performing redirect.',
    timeline: {
      discovered: new Date('2026-02-07T04:00:00Z'),
      reported: new Date('2026-02-07T04:05:00Z'),
      lastUpdated: new Date('2026-02-07T07:00:00Z'),
    },
  },
  {
    id: 'VULN-003',
    cveId: undefined,
    title: 'Missing Rate Limiting on Authentication Endpoints',
    description: 'Authentication endpoints lack rate limiting controls, enabling unlimited brute force attacks against user credentials.',
    severity: 'high',
    cvss: 7.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    affectedAsset: 'auth-service (10.0.1.35)',
    affectedComponent: 'app/api/auth/',
    discoveredAt: new Date('2026-02-07T04:00:00Z'),
    status: 'open',
    exploitAvailable: true,
    exploitInWild: true,
    cisaKev: false,
    patchAvailable: false,
    mitreTechniques: ['T1110'],
    threatIntel: {
      iocs: ['45.33.32.156', 'botnet-control.net'],
    },
    remediation: 'Implement rate limiting: max 5 failed attempts per minute per IP, account lockout for 15 minutes after 10 failures, CAPTCHA after 3 failures.',
    timeline: {
      discovered: new Date('2026-02-07T04:00:00Z'),
      reported: new Date('2026-02-07T04:05:00Z'),
      lastUpdated: new Date('2026-02-07T07:34:00Z'),
    },
  },
  {
    id: 'VULN-004',
    cveId: 'CVE-2023-44487',
    title: 'HTTP/2 Rapid Reset Attack Vulnerability',
    description: 'Application is potentially vulnerable to HTTP/2 rapid reset attacks which can cause denial of service through rapid stream resets.',
    severity: 'medium',
    cvss: 6.5,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
    affectedAsset: 'app-server-01 (10.0.1.25)',
    affectedComponent: 'Next.js Server',
    discoveredAt: new Date('2026-02-07T04:00:00Z'),
    status: 'resolved',
    exploitAvailable: true,
    exploitInWild: false,
    cisaKev: false,
    patchAvailable: true,
    patchId: 'Next.js 14.x',
    mitreTechniques: ['T1499'],
    remediation: 'Ensure Next.js is updated to version 14.x with HTTP/2 security patches applied.',
    timeline: {
      discovered: new Date('2026-02-07T04:00:00Z'),
      reported: new Date('2026-02-07T04:05:00Z'),
      lastUpdated: new Date('2026-02-07T06:00:00Z'),
    },
  },
  {
    id: 'VULN-005',
    cveId: undefined,
    title: 'Insecure Direct Object Reference (IDOR) - Message Access',
    description: 'Messages API allows users to access messages belonging to other users due to missing ownership verification, constituting horizontal privilege escalation.',
    severity: 'medium',
    cvss: 5.3,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    affectedAsset: 'db-server-01 (10.0.1.30)',
    affectedComponent: 'app/api/messages/[id]/route.ts',
    discoveredAt: new Date('2026-02-07T04:00:00Z'),
    status: 'open',
    exploitAvailable: true,
    exploitInWild: false,
    cisaKev: false,
    patchAvailable: false,
    mitreTechniques: ['T1008'],
    remediation: 'Implement ownership verification: add authorization checks verifying message.user_id == current_user.id before returning data.',
    timeline: {
      discovered: new Date('2026-02-07T04:00:00Z'),
      reported: new Date('2026-02-07T04:05:00Z'),
      lastUpdated: new Date('2026-02-07T07:00:00Z'),
    },
  },
  {
    id: 'VULN-006',
    cveId: undefined,
    title: 'Missing Security Headers - X-Frame-Options and X-Content-Type',
    description: 'Critical security headers are not configured, increasing vulnerability to clickjacking and MIME-sniffing attacks.',
    severity: 'low',
    cvss: 3.7,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
    affectedAsset: 'app-server-01 (10.0.1.25)',
    affectedComponent: 'app/layout.tsx',
    discoveredAt: new Date('2026-02-07T04:00:00Z'),
    status: 'open',
    exploitAvailable: false,
    exploitInWild: false,
    cisaKev: false,
    patchAvailable: false,
    mitreTechniques: ['T1189'],
    remediation: 'Add security headers middleware: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, X-XSS-Protection: 1; mode=block.',
    timeline: {
      discovered: new Date('2026-02-07T04:00:00Z'),
      reported: new Date('2026-02-07T04:05:00Z'),
      lastUpdated: new Date('2026-02-07T07:00:00Z'),
    },
  },
  {
    id: 'VULN-007',
    cveId: undefined,
    title: 'Server-Side Request Forgery (SSRF) in Auth Handler',
    description: 'Server-side request forgery vulnerability in authentication handler could allow attackers to make arbitrary HTTP requests from the server context.',
    severity: 'high',
    cvss: 8.6,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    affectedAsset: 'auth-service (10.0.1.35)',
    affectedComponent: 'app/auth/callback/route.ts',
    discoveredAt: new Date('2026-02-07T04:00:00Z'),
    status: 'open',
    exploitAvailable: true,
    exploitInWild: false,
    cisaKev: false,
    patchAvailable: false,
    mitreTechniques: ['T1190', 'T1083'],
    remediation: 'Implement SSRF protections: validate all URLs against allowlist, use fetch with restricted destinations, implement DNS rebinding protection.',
    timeline: {
      discovered: new Date('2026-02-07T04:00:00Z'),
      reported: new Date('2026-02-07T04:05:00Z'),
      lastUpdated: new Date('2026-02-07T07:00:00Z'),
    },
  },
];

// =====================================================
// INCIDENT DATABASE
// =====================================================

interface SecurityIncident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'investigating' | 'containing' | 'eradicating' | 'recovering' | 'resolved' | 'closed';
  type: string;
  category: string;
  confidenceScore: number;
  riskScore: number;
  affectedAssets: string[];
  indicators: string[];
  mitreTechniques: string[];
  attackVector: string;
  blastRadius: 'limited' | 'moderate' | 'extensive';
  exploitationLikelihood: 'unlikely' | 'possible' | 'likely' | 'imminent';
  description: string;
  aiSummary: string;
  rootCause: string;
  impact: string;
  scope: string;
  timeline: {
    timestamp: Date;
    event: string;
    action: string;
  }[];
  remediation: string[];
  containmentActions: string[];
  preventionActions: string[];
  assignee?: string;
  createdAt: Date;
  lastUpdated: Date;
}

const incidentDatabase: SecurityIncident[] = [
  {
    id: 'INC-2026-0207-001',
    title: 'CRITICAL: Active Brute Force Attack on Root Account',
    severity: 'critical',
    status: 'investigating',
    type: 'Unauthorized Access Attempt',
    category: 'Credential Attack',
    confidenceScore: 95,
    riskScore: 95,
    affectedAssets: ['auth-service', 'app-server-01'],
    indicators: ['91.207.174.23', 'Nmap Scripting Engine', '47 failed SSH attempts', 'Botnet infrastructure'],
    mitreTechniques: ['T1110', 'T1190', 'T1078'],
    attackVector: 'Network-based brute force against SSH/API authentication endpoints',
    blastRadius: 'limited',
    exploitationLikelihood: 'likely',
    description: 'Active brute force attack targeting root credentials from known malicious IP 91.207.174.23. Attack originating from botnet infrastructure detected via AlienVault OTX threat feed.',
    aiSummary: '⚠️ CRITICAL: Automated brute force attack detected targeting authentication infrastructure. Source IP (91.207.174.23) flagged as malicious with 95% confidence.',
    rootCause: 'Unauthenticated attack surface exposed to internet. Lack of rate limiting on authentication endpoints.',
    impact: 'Potential unauthorized system access, credential compromise, lateral movement capability.',
    scope: 'Authentication infrastructure and potentially all accessible systems.',
    timeline: [
      { timestamp: new Date('2026-02-07T05:15:00Z'), event: 'First attack attempt detected', action: 'alert_generated' },
      { timestamp: new Date('2026-02-07T05:15:30Z'), event: 'Threat intel match confirmed', action: 'ioc_confirmed' },
      { timestamp: new Date('2026-02-07T05:20:00Z'), event: 'Incident created - escalation initiated', action: 'incident_created' },
      { timestamp: new Date('2026-02-07T07:35:00Z'), event: 'Analyst investigation in progress', action: 'investigating' },
    ],
    remediation: [
      'BLOCK IP 91.207.174.23 at perimeter firewall immediately',
      'Implement fail2ban with aggressive lockout thresholds (3 attempts/5 min)',
      'Enable MFA for ALL privileged accounts within 4 hours',
    ],
    containmentActions: [
      'BLOCK source IP at perimeter firewall - PRIORITY 1',
      'Enable enhanced monitoring on auth-service',
    ],
    preventionActions: [
      'Deploy WAF with rate limiting rules for all auth endpoints',
      'Implement account lockout policy',
    ],
    assignee: 'SOC Analyst Team',
    createdAt: new Date('2026-02-07T05:15:00Z'),
    lastUpdated: new Date('2026-02-07T07:35:00Z'),
  },
  {
    id: 'INC-2026-0207-002',
    title: 'HIGH: Suspicious Login Pattern - Analyst Account',
    severity: 'high',
    status: 'new',
    type: 'Anomalous Authentication',
    category: 'Credential Attack',
    confidenceScore: 78,
    riskScore: 75,
    affectedAssets: ['auth-service', 'analyst@vishn.com account'],
    indicators: ['45.33.32.156', 'curl user-agent', '5 failed attempts'],
    mitreTechniques: ['T1110'],
    attackVector: 'API-based authentication attempts using curl from previously flagged IP',
    blastRadius: 'limited',
    exploitationLikelihood: 'possible',
    description: 'Multiple failed authentication attempts from non-standard client (curl) targeting analyst account.',
    aiSummary: '🔴 HIGH: Non-standard authentication pattern detected for analyst account. Source IP associated with brute force campaigns.',
    rootCause: 'Automated credential attack using non-standard client tools.',
    impact: 'Potential analyst credential compromise.',
    scope: 'Single user account.',
    timeline: [
      { timestamp: new Date('2026-02-07T07:34:58Z'), event: 'Suspicious login pattern detected', action: 'alert_generated' },
      { timestamp: new Date('2026-02-07T07:34:58Z'), event: 'Incident created - awaiting assignment', action: 'incident_created' },
    ],
    remediation: [
      'Temporarily lock analyst account pending verification',
      'Contact analyst via out-of-band channel',
      'Reset credentials immediately',
    ],
    containmentActions: [
      'Lock analyst@vishn.com account pending verification',
    ],
    preventionActions: [
      'Implement user agent validation for authentication',
    ],
    createdAt: new Date('2026-02-07T07:34:58Z'),
    lastUpdated: new Date('2026-02-07T07:34:58Z'),
  },
  {
    id: 'INC-2026-0207-003',
    title: 'CRITICAL: CVE-2024-3400 Command Injection - Active Exploitation Risk',
    severity: 'critical',
    status: 'investigating',
    type: 'Vulnerability Exploitation Risk',
    category: 'RCE Vulnerability',
    confidenceScore: 90,
    riskScore: 92,
    affectedAssets: ['app-server-01', 'app/api/chat/route.ts'],
    indicators: ['CVE-2024-3400', 'Next.js route handler', 'CVSS 9.8', 'CISA KEV'],
    mitreTechniques: ['T1190', 'T1059'],
    attackVector: 'Specially crafted HTTP requests to Next.js route handlers',
    blastRadius: 'extensive',
    exploitationLikelihood: 'imminent',
    description: 'Critical command injection vulnerability (CVSS 9.8) detected in Next.js route handler. CISA KEV status: EXPLOITED.',
    aiSummary: '🚨 CRITICAL: CVE-2024-3400 command injection vulnerability present. CVSS 9.8. CISA KEV: EXPLOITED.',
    rootCause: 'Unpatched Next.js installation (version < 14.2.0) with known RCE vulnerability.',
    impact: 'Complete system compromise, remote code execution.',
    scope: 'All applications on affected server.',
    timeline: [
      { timestamp: new Date('2026-02-07T04:00:00Z'), event: 'Vulnerability detected during scan', action: 'vulnerability_identified' },
      { timestamp: new Date('2026-02-07T04:05:00Z'), event: 'CISA KEV status confirmed', action: 'threat_intel_confirmed' },
      { timestamp: new Date('2026-02-07T04:10:00Z'), event: 'Incident created - P1 escalation', action: 'incident_created' },
    ],
    remediation: [
      'Upgrade Next.js to version 14.2.0 or later IMMEDIATELY',
      'Deploy emergency WAF rules blocking exploitation patterns',
    ],
    containmentActions: [
      'Deploy WAF rule to block exploitation attempts - IMMEDIATE',
    ],
    preventionActions: [
      'Implement automated vulnerability management with SLA-based patching',
    ],
    assignee: 'DevOps Team',
    createdAt: new Date('2026-02-07T04:00:00Z'),
    lastUpdated: new Date('2026-02-07T07:30:00Z'),
  },
  {
    id: 'INC-2026-0207-004',
    title: 'MEDIUM: Multiple Security Control Weaknesses',
    severity: 'medium',
    status: 'investigating',
    type: 'Security Control Weakness',
    category: 'Configuration Issue',
    confidenceScore: 85,
    riskScore: 65,
    affectedAssets: ['app/auth/callback/route.ts', 'app/api/auth/', 'app/api/messages/[id]/route.ts'],
    indicators: ['Open Redirect', 'Missing Rate Limiting', 'IDOR'],
    mitreTechniques: ['T1190'],
    attackVector: 'Various - depends on specific vulnerability exploitation',
    blastRadius: 'moderate',
    exploitationLikelihood: 'possible',
    description: 'Multiple security control weaknesses identified in authentication and authorization flows.',
    aiSummary: '🟡 MEDIUM: Multiple security control weaknesses identified.',
    rootCause: 'Inadequate security controls during development.',
    impact: 'Increased attack surface.',
    scope: 'Authentication subsystem.',
    timeline: [
      { timestamp: new Date('2026-02-07T04:00:00Z'), event: 'Multiple vulnerabilities identified', action: 'vulnerabilities_identified' },
    ],
    remediation: [
      'Implement Open Redirect fix with strict URL whitelist',
      'Deploy rate limiting on all auth endpoints',
    ],
    containmentActions: [
      'Deploy temporary WAF rules for Open Redirect patterns',
    ],
    preventionActions: [
      'Add security code review requirements to development process',
    ],
    assignee: 'Security Engineering Team',
    createdAt: new Date('2026-02-07T04:00:00Z'),
    lastUpdated: new Date('2026-02-07T07:00:00Z'),
  },
];

// =====================================================
// COMPLIANCE STATUS
// =====================================================

interface ComplianceFramework {
  framework: string;
  score: number;
  controlsTotal: number;
  controlsPassed: number;
  controlsFailed: number;
  trend: number;
  controls: Array<{
    id: string;
    name: string;
    status: 'passed' | 'failed' | 'degraded' | 'not_tested';
    severity: 'critical' | 'high' | 'medium' | 'low';
    lastTested: Date;
  }>;
}

const complianceStatus: ComplianceFramework[] = [
  {
    framework: 'SOC 2 Type II',
    score: 68,
    controlsTotal: 12,
    controlsPassed: 8,
    controlsFailed: 4,
    trend: -6,
    controls: [
      { id: 'CC6.1', name: 'Logical Access Control', status: 'failed', severity: 'high', lastTested: new Date('2026-02-07') },
      { id: 'CC6.6', name: 'Security Headers', status: 'failed', severity: 'medium', lastTested: new Date('2026-02-07') },
      { id: 'CC7.2', name: 'System Monitoring', status: 'failed', severity: 'medium', lastTested: new Date('2026-02-07') },
    ],
  },
  {
    framework: 'ISO 27001',
    score: 66,
    controlsTotal: 15,
    controlsPassed: 10,
    controlsFailed: 5,
    trend: -4,
    controls: [
      { id: 'A.9.4.3', name: 'Password Policy Enforcement', status: 'failed', severity: 'high', lastTested: new Date('2026-02-07') },
      { id: 'A.12.4.1', name: 'Logging and Monitoring', status: 'failed', severity: 'medium', lastTested: new Date('2026-02-07') },
      { id: 'A.14.2.1', name: 'Secure Development Lifecycle', status: 'failed', severity: 'medium', lastTested: new Date('2026-02-07') },
    ],
  },
  {
    framework: 'GDPR',
    score: 72,
    controlsTotal: 8,
    controlsPassed: 6,
    controlsFailed: 2,
    trend: -3,
    controls: [
      { id: 'Art.32', name: 'Data Access Logging', status: 'failed', severity: 'medium', lastTested: new Date('2026-02-07') },
    ],
  },
  {
    framework: 'PCI DSS',
    score: 65,
    controlsTotal: 15,
    controlsPassed: 10,
    controlsFailed: 5,
    trend: -8,
    controls: [
      { id: 'Req.8.2', name: 'Password Policy Enforcement', status: 'failed', severity: 'high', lastTested: new Date('2026-02-07') },
      { id: 'Req.6.4', name: 'Application Security Controls', status: 'failed', severity: 'medium', lastTested: new Date('2026-02-07') },
    ],
  },
];

// =====================================================
// MITRE ATT&CK MAPPING
// =====================================================

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  detections: number;
  lastDetected: Date;
  confidence: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  mitigations: string[];
  affectedAssets: string[];
}

const mitreTechniques: MitreTechnique[] = [
  { id: 'T1110', name: 'Brute Force', tactic: 'credential_access', detections: 52, lastDetected: new Date('2026-02-07T07:34:58Z'), confidence: 95, severity: 'critical', mitigations: ['Rate limiting', 'MFA', 'Account lockout'], affectedAssets: ['auth-service'] },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial_access', detections: 3, lastDetected: new Date('2026-02-07T07:00:00Z'), confidence: 90, severity: 'critical', mitigations: ['Patch vulnerabilities', 'Deploy WAF'], affectedAssets: ['app-server-01'] },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'initial_access', detections: 1, lastDetected: new Date('2026-02-07T07:35:12Z'), confidence: 85, severity: 'high', mitigations: ['MFA enforcement', 'Session monitoring'], affectedAssets: ['auth-service'] },
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution', detections: 1, lastDetected: new Date('2026-02-07T07:15:00Z'), confidence: 75, severity: 'high', mitigations: ['Disable unnecessary interpreters', 'Process monitoring'], affectedAssets: ['app-server-01'] },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'discovery', detections: 5, lastDetected: new Date('2026-02-07T07:20:00Z'), confidence: 70, severity: 'medium', mitigations: ['Limit system information exposure'], affectedAssets: ['app-server-01', 'db-server-01'] },
];

// =====================================================
// THREAT INTELLIGENCE
// =====================================================

interface ThreatIntelIOC {
  indicator: string;
  type: 'IPv4' | 'IPv6' | 'Domain' | 'Hash' | 'CVE' | 'URL';
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  source: string;
  description: string;
  tags: string[];
  firstSeen: Date;
  lastSeen: Date;
  attackCount: number;
}

const threatIntelIOCs: ThreatIntelIOC[] = [
  { indicator: '91.207.174.23', type: 'IPv4', severity: 'critical', confidence: 95, source: 'AlienVault OTX', description: 'Known malicious IP - botnet infrastructure', tags: ['botnet', 'brute-force'], firstSeen: new Date('2024-06-15'), lastSeen: new Date('2026-02-07T07:30:00Z'), attackCount: 47 },
  { indicator: '45.33.32.156', type: 'IPv4', severity: 'high', confidence: 78, source: 'AbuseIPDB', description: 'Suspicious activity - SSH brute force', tags: ['brute-force', 'ssh'], firstSeen: new Date('2025-01-20'), lastSeen: new Date('2026-02-07T07:34:58Z'), attackCount: 5 },
  { indicator: 'CVE-2024-3400', type: 'CVE', severity: 'critical', confidence: 100, source: 'CISA KEV', description: 'Command injection - actively exploited', tags: ['cisa-kev', 'rce'], firstSeen: new Date('2024-03-22'), lastSeen: new Date('2026-02-07'), attackCount: 1000 },
];

// =====================================================
// ASSET INVENTORY
// =====================================================

interface Asset {
  hostname: string;
  ipAddress: string;
  assetType: 'server' | 'workstation' | 'container' | 'cloud' | 'network' | 'database' | 'application';
  os?: string;
  services: Array<{ port: number; service: string; version: string; status: 'open' | 'filtered' | 'closed' }>;
  vulnerabilities: { critical: number; high: number; medium: number; low: number };
  riskScore: number;
  complianceScore: number;
  lastScan: Date;
  status: 'healthy' | 'warning' | 'critical';
}

const assetInventory: Asset[] = [
  { hostname: 'app-server-01', ipAddress: '10.0.1.25', assetType: 'server', os: 'Ubuntu 22.04 LTS', services: [{ port: 443, service: 'HTTPS', version: 'Next.js 14.x', status: 'open' }, { port: 80, service: 'HTTP', version: 'Next.js 14.x', status: 'open' }, { port: 22, service: 'SSH', version: 'OpenSSH 8.9', status: 'open' }], vulnerabilities: { critical: 1, high: 2, medium: 1, low: 1 }, riskScore: 92, complianceScore: 62, lastScan: new Date('2026-02-07T07:36:00Z'), status: 'critical' },
  { hostname: 'db-server-01', ipAddress: '10.0.1.30', assetType: 'database', os: 'PostgreSQL 15.2', services: [{ port: 5432, service: 'PostgreSQL', version: '15.2', status: 'open' }], vulnerabilities: { critical: 0, high: 0, medium: 1, low: 2 }, riskScore: 55, complianceScore: 72, lastScan: new Date('2026-02-07T07:36:00Z'), status: 'warning' },
  { hostname: 'auth-service', ipAddress: '10.0.1.35', assetType: 'application', os: 'Node.js 20.x', services: [{ port: 3000, service: 'Next.js App', version: '20.x', status: 'open' }, { port: 5432, service: 'Internal DB', version: 'PostgreSQL', status: 'filtered' }], vulnerabilities: { critical: 0, high: 2, medium: 0, low: 1 }, riskScore: 68, complianceScore: 65, lastScan: new Date('2026-02-07T07:36:00Z'), status: 'warning' },
];

// =====================================================
// MAIN SCAN ENGINE
// =====================================================

interface ScanResult {
  scanId: string;
  timestamp: Date;
  duration: string;
  scanType: string;
  timeRange: string;
  securityScore: number;
  securityScoreTrend: number;
  riskLevel: string;
  vulnerabilities: { total: number; critical: number; high: number; medium: number; low: number; open: number; inProgress: number; resolved: number };
  vulnerabilitiesList?: VulnerabilityItem[];
  incidents: { total: number; critical: number; high: number; active: number; new: number; investigating: number };
  compliance: { overallScore: number; frameworks: ComplianceFramework[] };
  mitreTechniques: MitreTechnique[];
  threatIntel: { activeIOCs: number; criticalThreats: number; iocs: ThreatIntelIOC[] };
  assets: Asset[];
  criticalFindings: Array<{ id: string; title: string; severity: string; status: string; affectedAsset: string; remediation: string; priority: number }>;
  aiSummary: string;
  scanHealth: { status: 'healthy' | 'degraded' | 'failed'; message: string; componentsChecked: number; componentsHealthy: number };
}

export function executeSecurityScan(config: ScanConfig): ScanResult {
  const startTime = Date.now();
  const scanId = `SOC-SCAN-${new Date().toISOString().replace(/[-:]/g, '').slice(0, 14)}`;
  
  const criticalVulns = vulnerabilityDatabase.filter(v => v.severity === 'critical' && v.status === 'open');
  const highVulns = vulnerabilityDatabase.filter(v => v.severity === 'high' && v.status === 'open');
  const mediumVulns = vulnerabilityDatabase.filter(v => v.severity === 'medium');
  const lowVulns = vulnerabilityDatabase.filter(v => v.severity === 'low');
  
  const criticalIncidents = incidentDatabase.filter(i => i.severity === 'critical' && !['resolved', 'closed'].includes(i.status));
  const activeIncidents = incidentDatabase.filter(i => !['resolved', 'closed'].includes(i.status));
  
  const securityScore = Math.max(0, 100 - (criticalVulns.length * 25) - (highVulns.length * 15) - (mediumVulns.length * 5) - (lowVulns.length * 2));
  
  const riskLevel = securityScore >= 80 ? 'LOW' : securityScore >= 60 ? 'MEDIUM' : securityScore >= 40 ? 'HIGH' : 'CRITICAL';
  
  const aiSummary = `SOC Assessment Complete | Risk Level: ${riskLevel} (${securityScore}/100) | ${criticalVulns.length} Critical Vulnerabilities | ${criticalIncidents.length} Critical Incidents | Priority: Block IP 91.207.174.23, Patch CVE-2024-3400`;
  
  interface VulnerabilityItem {
    id: string;
    type?: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description?: string;
    cvss?: number;
    cve?: string;
    affectedComponent?: string;
    remediation?: string;
    confidence?: number;
  }

  const vulnerabilitiesList: VulnerabilityItem[] = vulnerabilityDatabase.map(v => ({
    id: v.id,
    type: 'vulnerability',
    severity: v.severity,
    title: v.title,
    description: v.description,
    cvss: v.cvss,
    cve: v.cveId,
    affectedComponent: v.affectedComponent,
    remediation: v.remediation,
    confidence: v.exploitInWild ? 95 : v.exploitAvailable ? 75 : 50,
  }));

  const endTime = Date.now();
  
  return {
    scanId,
    timestamp: new Date(),
    duration: `${((endTime - startTime) / 1000).toFixed(2)}s`,
    scanType: config.scanType,
    timeRange: config.timeRange,
    securityScore,
    securityScoreTrend: -5,
    riskLevel,
    vulnerabilities: { total: vulnerabilityDatabase.length, critical: criticalVulns.length, high: highVulns.length, medium: mediumVulns.length, low: lowVulns.length, open: vulnerabilityDatabase.filter(v => v.status === 'open').length, inProgress: vulnerabilityDatabase.filter(v => v.status === 'in_progress').length, resolved: vulnerabilityDatabase.filter(v => v.status === 'resolved').length },
    vulnerabilitiesList,
    incidents: { total: incidentDatabase.length, critical: criticalIncidents.length, high: incidentDatabase.filter(i => i.severity === 'high' && !['resolved', 'closed'].includes(i.status)).length, active: activeIncidents.length, new: incidentDatabase.filter(i => i.status === 'new').length, investigating: incidentDatabase.filter(i => i.status === 'investigating').length },
    compliance: { overallScore: Math.round(complianceStatus.reduce((acc, f) => acc + f.score, 0) / complianceStatus.length), frameworks: complianceStatus },
    mitreTechniques: mitreTechniques.filter(t => t.detections > 0),
    threatIntel: { activeIOCs: threatIntelIOCs.length, criticalThreats: threatIntelIOCs.filter(i => i.severity === 'critical').length, iocs: threatIntelIOCs },
    assets: assetInventory,
    criticalFindings: [
      { id: 'CF-001', title: 'CVE-2024-3400 Command Injection in Next.js', severity: 'critical', status: 'open', affectedAsset: 'app-server-01', remediation: 'Upgrade Next.js to 14.2.0+', priority: 1 },
      { id: 'CF-002', title: 'Active Brute Force Attack from Botnet IP', severity: 'critical', status: 'investigating', affectedAsset: 'auth-service', remediation: 'Block IP 91.207.174.23 immediately', priority: 2 },
    ],
    aiSummary,
    scanHealth: { status: 'healthy', message: 'All scan components operating normally', componentsChecked: 8, componentsHealthy: 8 },
  };
}

export { vulnerabilityDatabase, incidentDatabase, complianceStatus, mitreTechniques, threatIntelIOCs, assetInventory };
export type { Vulnerability, SecurityIncident, ComplianceFramework, MitreTechnique, ThreatIntelIOC, Asset, ScanResult };
