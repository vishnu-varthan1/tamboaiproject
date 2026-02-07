// SOC Platform - Comprehensive Security Scan Results
// Scan Execution Time: 2026-02-07T07:36:00Z
// Scan ID: SOC-SCAN-20260207-073600

import { 
  ThreatLevel, 
  Vulnerability, 
  SecurityRecommendation,
  MitreAttack 
} from './security-types';

// ============================================================================
// 1. ENDPOINT SECURITY SCAN RESULTS
// ============================================================================

export interface EndpointScanResult {
  hostname: string;
  ipAddress: string;
  os: string;
  status: 'healthy' | 'warning' | 'critical';
  openPorts: { port: number; service: string; status: string }[];
  securityFindings: {
    severity: ThreatLevel;
    finding: string;
    cve?: string;
  }[];
  lastScan: Date;
}

export const endpointScanResults: EndpointScanResult[] = [
  {
    hostname: 'app-server-01',
    ipAddress: '10.0.1.25',
    os: 'Ubuntu 22.04 LTS',
    status: 'critical',
    openPorts: [
      { port: 443, service: 'HTTPS', status: 'open' },
      { port: 80, service: 'HTTP', status: 'open' },
      { port: 22, service: 'SSH', status: 'open' },
    ],
    securityFindings: [
      { severity: 'critical', finding: 'CVE-2024-3400 Command Injection in Next.js', cve: 'CVE-2024-3400' },
      { severity: 'high', finding: 'Open Redirect vulnerability in OAuth flow', cve: undefined },
      { severity: 'low', finding: 'SSH banner reveals OS version', cve: 'N/A' },
      { severity: 'low', finding: 'HTTP server tokens enabled', cve: undefined },
    ],
    lastScan: new Date('2026-02-07T07:36:00Z'),
  },
  {
    hostname: 'db-server-01',
    ipAddress: '10.0.1.30',
    os: 'PostgreSQL 15.2',
    status: 'warning',
    openPorts: [
      { port: 5432, service: 'PostgreSQL', status: 'open' },
    ],
    securityFindings: [
      { severity: 'medium', finding: 'SSL/TLS certificate expires in 13 days', cve: 'N/A' },
      { severity: 'low', finding: 'Connection logging set to minimal', cve: undefined },
      { severity: 'low', finding: 'IDOR vulnerability in message API', cve: undefined },
    ],
    lastScan: new Date('2026-02-07T07:36:00Z'),
  },
  {
    hostname: 'auth-service',
    ipAddress: '10.0.1.35',
    os: 'Node.js 20.x',
    status: 'warning',
    openPorts: [
      { port: 3000, service: 'Next.js App', status: 'open' },
      { port: 5432, service: 'Internal DB', status: 'filtered' },
    ],
    securityFindings: [
      { severity: 'high', finding: 'Missing rate limiting on auth endpoints', cve: undefined },
      { severity: 'low', finding: 'Missing security headers', cve: undefined },
    ],
    lastScan: new Date('2026-02-07T07:36:00Z'),
  },
];

// ============================================================================
// 2. NETWORK TRAFFIC ANALYSIS
// ============================================================================

export interface NetworkTrafficEvent {
  id: string;
  timestamp: Date;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  bytes: number;
  risk: ThreatLevel;
  indicator: string;
  description: string;
}

export const networkTrafficAnalysis: NetworkTrafficEvent[] = [
  {
    id: 'NET-001',
    timestamp: new Date('2026-02-07T07:15:15Z'),
    sourceIP: '10.0.1.25',
    destinationIP: '203.0.113.45',
    protocol: 'HTTPS',
    bytes: 45892,
    risk: 'low',
    indicator: 'API Call',
    description: 'Routine API call to external service',
  },
  {
    id: 'NET-002',
    timestamp: new Date('2026-02-07T07:12:33Z'),
    sourceIP: '10.0.1.25',
    destinationIP: '198.51.100.22',
    protocol: 'DNS',
    bytes: 256,
    risk: 'medium',
    indicator: 'External DNS Query',
    description: 'DNS query to unknown external domain - investigation recommended',
  },
  {
    id: 'NET-003',
    timestamp: new Date('2026-02-07T07:35:42Z'),
    sourceIP: '10.0.1.30',
    destinationIP: '10.0.1.25',
    protocol: 'PostgreSQL',
    bytes: 15420,
    risk: 'low',
    indicator: 'Database Query',
    description: 'Standard database query traffic',
  },
  {
    id: 'NET-004',
    timestamp: new Date('2026-02-07T07:30:00Z'),
    sourceIP: '91.207.174.23',
    destinationIP: '10.0.1.35',
    protocol: 'SSH',
    bytes: 2048,
    risk: 'critical',
    indicator: 'Brute Force Attack',
    description: 'Multiple connection attempts from known malicious IP - BLOCKED',
  },
];

// ============================================================================
// 3. USER AUTHENTICATION LOGS
// ============================================================================

export interface AuthLogEvent {
  id: string;
  timestamp: Date;
  userId: string;
  username: string;
  action: string;
  status: 'success' | 'failure';
  ipAddress: string;
  userAgent: string;
  risk: ThreatLevel;
  anomalyScore: number;
  description?: string;
}

export const authLogAnalysis: AuthLogEvent[] = [
  {
    id: 'AUTH-001',
    timestamp: new Date('2026-02-07T07:35:12Z'),
    userId: 'user-001',
    username: 'admin@vishn.com',
    action: 'LOGIN_SUCCESS',
    status: 'success',
    ipAddress: '192.168.1.100',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    risk: 'low',
    anomalyScore: 10,
  },
  {
    id: 'AUTH-002',
    timestamp: new Date('2026-02-07T07:34:58Z'),
    userId: 'user-002',
    username: 'analyst@vishn.com',
    action: 'LOGIN_FAILURE',
    status: 'failure',
    ipAddress: '45.33.32.156',
    userAgent: 'curl/7.68.0',
    risk: 'high',
    anomalyScore: 85,
    description: 'Multiple failed login attempts from non-standard user agent',
  },
  {
    id: 'AUTH-003',
    timestamp: new Date('2026-02-07T07:30:22Z'),
    userId: 'user-003',
    username: 'dev@vishn.com',
    action: 'PASSWORD_CHANGE',
    status: 'success',
    ipAddress: '10.0.1.50',
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    risk: 'low',
    anomalyScore: 15,
  },
  {
    id: 'AUTH-004',
    timestamp: new Date('2026-02-07T05:15:00Z'),
    userId: 'unknown',
    username: 'root',
    action: 'LOGIN_ATTEMPT',
    status: 'failure',
    ipAddress: '91.207.174.23',
    userAgent: 'Nmap Scripting Engine',
    risk: 'critical',
    anomalyScore: 95,
    description: 'Brute force attack attempt detected - root account targeting',
  },
];

// ============================================================================
// 4. APPLICATION VULNERABILITY SCAN
// ============================================================================

export const vulnerabilityScanResults: Vulnerability[] = [
  {
    id: 'VULN-001',
    cve: 'CVE-2024-3400',
    title: 'Command Injection in Next.js Route Handler',
    severity: 'critical',
    cvss: 9.8,
    description: 'A critical command injection vulnerability exists in Next.js route handler processing. This vulnerability allows unauthenticated remote attackers to execute arbitrary commands on the server. Actively exploited in the wild per CISA KEV catalog.',
    affectedComponent: 'app/api/chat/route.ts',
    remediation: 'Upgrade to Next.js 14.2.0 or later immediately. Deploy WAF rules blocking exploitation patterns as interim mitigation.',
    status: 'open',
  },
  {
    id: 'VULN-002',
    cve: null,
    title: 'Open Redirect in OAuth Callback Handler',
    severity: 'high',
    cvss: 7.1,
    description: 'Open redirect vulnerability in OAuth callback handler allows attackers to redirect victims to malicious sites. This can be used in phishing campaigns to increase credibility.',
    affectedComponent: 'app/auth/callback/route.ts',
    remediation: 'Implement strict redirect URL validation whitelist. Validate all redirect URLs against approved list server-side.',
    status: 'open',
  },
  {
    id: 'VULN-003',
    cve: null,
    title: 'Missing Rate Limiting on Authentication Endpoints',
    severity: 'high',
    cvss: 7.5,
    description: 'Authentication endpoints lack rate limiting controls, enabling brute force attacks. This vulnerability has been actively exploited in recent incidents.',
    affectedComponent: 'app/api/auth/',
    remediation: 'Implement rate limiting with following constraints: max 5 failed attempts per minute per IP, account lockout for 15 minutes after 10 failures, CAPTCHA after 3 failures.',
    status: 'open',
  },
  {
    id: 'VULN-004',
    cve: 'CVE-2023-44487',
    title: 'HTTP/2 Rapid Reset Attack Vulnerability',
    severity: 'medium',
    cvss: 6.5,
    description: 'Application is potentially vulnerable to HTTP/2 rapid reset attacks which can cause denial of service.',
    affectedComponent: 'Next.js Server',
    remediation: 'Ensure Next.js is updated to version 14.x with HTTP/2 security patches applied. Configure appropriate request timeouts.',
    status: 'resolved',
  },
  {
    id: 'VULN-005',
    cve: null,
    title: 'Insecure Direct Object Reference (IDOR) - Message Access',
    severity: 'medium',
    cvss: 5.3,
    description: 'Messages API allows users to access messages belonging to other users due to missing ownership verification. This constitutes a horizontal privilege escalation.',
    affectedComponent: 'app/api/messages/[id]/route.ts',
    remediation: 'Implement ownership verification in all API endpoints. Add authorization checks verifying message.user_id == current_user.id before returning data.',
    status: 'open',
  },
  {
    id: 'VULN-006',
    cve: null,
    title: 'Missing Security Headers - X-Frame-Options and X-Content-Type',
    severity: 'low',
    cvss: 3.7,
    description: 'Critical security headers (X-Frame-Options, X-Content-Type-Options) are not configured, increasing vulnerability to clickjacking and MIME-sniffing attacks.',
    affectedComponent: 'app/layout.tsx',
    remediation: 'Add security headers middleware: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, X-XSS-Protection: 1; mode=block',
    status: 'open',
  },
  {
    id: 'VULN-007',
    cve: 'CVE-2024-29041',
    title: 'Server-Side Request Forgery (SSRF) in Auth Handler',
    severity: 'high',
    cvss: 8.6,
    description: 'Server-side request forgery vulnerability in authentication handler could allow attackers to make arbitrary HTTP requests from the server context.',
    affectedComponent: 'app/auth/callback/route.ts',
    remediation: 'Implement SSRF protection: validate all URLs against allowlist, use fetch with restricted destinations, implement DNS rebinding protection.',
    status: 'open',
  },
];

// ============================================================================
// 5. MITRE ATT&CK CORRELATION
// ============================================================================

export const mitreAttackCorrelations: (MitreAttack & { 
  detected: boolean; 
  count: number; 
  lastDetected: Date;
})[] = [
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'initial_access',
    technique: 'T1190',
    description: 'Exploitation of web applications to gain initial access. Adversaries may attempt to exploit web-facing applications to gain access to internal network.',
    detection: 'Monitor for unusual web traffic patterns, failed login attempts, abnormal request sizes, and known exploitation signatures.',
    detected: true,
    count: 3,
    lastDetected: new Date('2026-02-07T07:00:00Z'),
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'credential_access',
    technique: 'T1110',
    description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password policies are weak.',
    detection: 'Monitor failed login attempts by account and IP address. Alert on unusual geographic locations and non-standard user agents.',
    detected: true,
    count: 52,
    lastDetected: new Date('2026-02-07T07:34:58Z'),
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'initial_access',
    technique: 'T1078',
    description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining initial access.',
    detection: 'Monitor account usage patterns, privilege changes, and login activity from unusual locations or devices.',
    detected: true,
    count: 1,
    lastDetected: new Date('2026-02-07T07:35:12Z'),
  },
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'execution',
    technique: 'T1059',
    description: 'Adversaries may abuse command and script interpreters to execute commands, typically to obtain initial access or elevate privileges.',
    detection: 'Monitor process execution with command line arguments, especially those originating from web processes.',
    detected: true,
    count: 1,
    lastDetected: new Date('2026-02-07T07:15:00Z'),
  },
  {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'discovery',
    technique: 'T1082',
    description: 'An adversary may attempt to get detailed information about the operating system and hardware.',
    detection: 'Monitor system information queries, network enumeration tools, and reconnaissance activities.',
    detected: true,
    count: 5,
    lastDetected: new Date('2026-02-07T07:20:00Z'),
  },
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'initial_access',
    technique: 'T1566',
    description: 'Adversaries may send phishing messages to gain access to victim systems.',
    detection: 'Email security gateways, URL analysis, user reporting mechanisms.',
    detected: false,
    count: 0,
    lastDetected: new Date('1970-01-01T00:00:00Z'),
  },
  {
    id: 'T1041',
    name: 'Exfiltration Over C2',
    tactic: 'exfiltration',
    technique: 'T1041',
    description: 'Adversaries may steal data by exfiltrating it over command and control channel.',
    detection: 'Network monitoring, C2 detection, unusual outbound traffic patterns.',
    detected: false,
    count: 0,
    lastDetected: new Date('1970-01-01T00:00:00Z'),
  },
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'credential_access',
    technique: 'T1003',
    description: 'Adversaries may attempt to dump credentials from the operating system.',
    detection: 'Monitor LSASS access, process memory dumps, and credential manager access.',
    detected: false,
    count: 0,
    lastDetected: new Date('1970-01-01T00:00:00Z'),
  },
];

// ============================================================================
// 6. THREAT INTELLIGENCE FEED CORRELATION
// ============================================================================

export interface ThreatIntelMatch {
  indicator: string;
  type: 'IP' | 'Domain' | 'Hash' | 'URL' | 'CVE';
  source: string;
  confidence: number;
  severity: ThreatLevel;
  description: string;
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
}

export const threatIntelMatches: ThreatIntelMatch[] = [
  {
    indicator: '91.207.174.23',
    type: 'IP',
    source: 'AlienVault OTX',
    confidence: 95,
    severity: 'critical',
    description: 'Known malicious IP address - part of active botnet infrastructure. Associated with distributed brute force attacks and credential stuffing campaigns.',
    firstSeen: new Date('2024-06-15T00:00:00Z'),
    lastSeen: new Date('2026-02-07T07:30:00Z'),
    tags: ['botnet', 'brute-force', 'malicious', 'credential-stuffing', 'active-threat'],
  },
  {
    indicator: '45.33.32.156',
    type: 'IP',
    source: 'AbuseIPDB',
    confidence: 78,
    severity: 'high',
    description: 'Suspicious activity - historical SSH brute force attempts and port scanning behavior detected.',
    firstSeen: new Date('2025-01-20T00:00:00Z'),
    lastSeen: new Date('2026-02-07T07:34:58Z'),
    tags: ['brute-force', 'ssh', 'scanner', 'suspicious'],
  },
  {
    indicator: 'CVE-2024-3400',
    type: 'CVE',
    source: 'CISA KEV',
    confidence: 100,
    severity: 'critical',
    description: 'Command injection vulnerability in Next.js - actively exploited in the wild. CISA Emergency Directive issued.',
    firstSeen: new Date('2024-03-22T00:00:00Z'),
    lastSeen: new Date('2026-02-07T00:00:00Z'),
    tags: ['cisa-kev', 'actively-exploited', 'rce', 'command-injection', 'nextjs'],
  },
];

// ============================================================================
// 7. SECURITY INCIDENTS IDENTIFICATION
// ============================================================================

export interface SecurityIncident {
  id: string;
  title: string;
  severity: ThreatLevel;
  status: 'new' | 'investigating' | 'contained' | 'resolved' | 'closed';
  lifecycleState: 'New' | 'Investigating' | 'Containing' | 'Eradicating' | 'Recovering' | 'Closed';
  type: string;
  affectedAssets: string[];
  indicators: string[];
  mitreTechniques: string[];
  createdAt: Date;
  lastUpdated: Date;
  confidenceScore: number;
  riskScore: number;
  blastRadius: 'limited' | 'moderate' | 'extensive';
  exploitationLikelihood: 'unlikely' | 'possible' | 'likely' | 'imminent';
  description: string;
  aiSummary: string;
  rootCause: string;
  attackVector: string;
  impact: string;
  scope: string;
  remediation: string[];
  containmentActions: string[];
  preventionMeasures: string[];
}

export const identifiedIncidents: SecurityIncident[] = [
  {
    id: 'INC-2026-0207-001',
    title: 'CRITICAL: Active Brute Force Attack on Root Account',
    severity: 'critical',
    status: 'investigating',
    lifecycleState: 'Investigating',
    type: 'Unauthorized Access Attempt',
    affectedAssets: ['auth-service', 'app-server-01', '10.0.1.35'],
    indicators: ['91.207.174.23', 'Nmap Scripting Engine', '47+ failed login attempts', 'SSH brute force', 'Botnet infrastructure'],
    mitreTechniques: ['T1110', 'T1190', 'T1078'],
    createdAt: new Date('2026-02-07T05:15:00Z'),
    lastUpdated: new Date('2026-02-07T07:35:00Z'),
    confidenceScore: 95,
    riskScore: 95,
    blastRadius: 'limited',
    exploitationLikelihood: 'likely',
    description: 'Active brute force attack targeting root account from known malicious IP 91.207.174.23. Attack originating from botnet infrastructure detected via AlienVault OTX threat feed. 47 failed authentication attempts recorded in past 2 hours.',
    aiSummary: '⚠️ CRITICAL SEVERITY: Automated brute force attack detected targeting authentication infrastructure. Source IP (91.207.174.23) flagged as malicious with 95% confidence by threat intelligence feeds. Attack pattern consistent with T1110 (Brute Force) MITRE ATT&CK technique. All attempts have been BLOCKED but persistent targeting indicates ongoing threat. IMMEDIATE CONTAINMENT REQUIRED.',
    rootCause: 'Unauthenticated attack surface exposed to internet allowing automated credential attacks. Lack of rate limiting on authentication endpoints enables unlimited retry attempts.',
    attackVector: 'Network-based brute force against SSH/API authentication endpoints from botnet infrastructure',
    impact: 'Potential unauthorized system access, credential compromise, lateral movement capability, data exfiltration risk',
    scope: 'Authentication infrastructure and potentially all systems accessible via compromised credentials',
    remediation: [
      'Block source IP 91.207.174.23 at perimeter firewall and WAF immediately',
      'Implement fail2ban or equivalent with aggressive lockout thresholds (3 attempts/5 min)',
      'Enable MFA for ALL privileged accounts within 4 hours',
      'Review authentication logs for any successful compromise from this IP',
      'Implement IP reputation-based access controls at perimeter',
      'Consider geo-blocking non-operational regions',
    ],
    containmentActions: [
      'BLOCK IP 91.207.174.23 at perimeter firewall - PRIORITY 1',
      'Enable enhanced monitoring on auth-service for continued attack patterns',
      'Temporarily increase login failure threshold alerts',
      'Verify no successful authentications from threat IP',
    ],
    preventionMeasures: [
      'Deploy WAF with rate limiting rules for all auth endpoints',
      'Implement account lockout policy: 5 failures = 15 minute lockout',
      'Deploy CAPTCHA after 3 failed attempts',
      'Enable enhanced logging on all authentication events',
      'Review and update incident response playbook PB-001',
    ],
  },
  {
    id: 'INC-2026-0207-002',
    title: 'HIGH: Suspicious Authentication Pattern - Analyst Account',
    severity: 'high',
    status: 'new',
    lifecycleState: 'New',
    type: 'Anomalous Authentication',
    affectedAssets: ['auth-service', 'analyst@vishn.com account'],
    indicators: ['45.33.32.156', 'curl user-agent', '5 failed attempts', 'Non-standard client', 'SSH scanner history'],
    mitreTechniques: ['T1110'],
    createdAt: new Date('2026-02-07T07:34:58Z'),
    lastUpdated: new Date('2026-02-07T07:34:58Z'),
    confidenceScore: 78,
    riskScore: 75,
    blastRadius: 'limited',
    exploitationLikelihood: 'possible',
    description: 'Multiple failed authentication attempts from non-standard client (curl) targeting analyst account. Source IP previously flagged for SSH brute force activity on AbuseIPDB. Behavior inconsistent with typical user activity patterns.',
    aiSummary: '🔴 HIGH SEVERITY: Non-standard authentication pattern detected for analyst account. Source IP 45.33.32.156 associated with brute force campaigns (78% confidence). Client behavior (curl user-agent) inconsistent with typical analyst workflow. INVESTIGATION REQUIRED to determine if credential compromise or targeted attack.',
    rootCause: 'Automated credential attack using non-standard client tools. Lack of user agent validation and rate limiting enabling sustained attacks.',
    attackVector: 'API-based authentication attempts using curl from previously flagged IP address',
    impact: 'Potential analyst credential compromise, unauthorized access to analyst resources and data',
    scope: 'Single user account - analyst@vishn.com',
    remediation: [
      'Temporarily lock analyst account pending identity verification',
      'Contact analyst via out-of-band channel (phone/SMS) for verification',
      'Reset account credentials immediately',
      'Review recent account activity for unauthorized actions',
      'Update firewall rules to flag repeated failures from this IP',
      'Investigate if this is part of larger campaign against organization',
    ],
    containmentActions: [
      'Lock analyst@vishn.com account pending verification',
      'Enable enhanced monitoring on account activity',
      'Preserve logs for forensic analysis',
    ],
    preventionMeasures: [
      'Implement user agent validation for authentication',
      'Add alerts for non-standard clients accessing auth endpoints',
      'Consider requiring corporate VPN for authentication',
      'Review password policy for analyst accounts',
    ],
  },
  {
    id: 'INC-2026-0207-003',
    title: 'CRITICAL: CVE-2024-3400 Command Injection - Active Exploitation Risk',
    severity: 'critical',
    status: 'investigating',
    lifecycleState: 'Investigating',
    type: 'Vulnerability Exploitation Risk',
    affectedAssets: ['app-server-01', 'app/api/chat/route.ts', '10.0.1.25'],
    indicators: ['CVE-2024-3400', 'Next.js route handler', 'CVSS 9.8', 'CISA KEV', 'Active exploitation in wild'],
    mitreTechniques: ['T1190', 'T1059', 'T1566'],
    createdAt: new Date('2026-02-07T04:00:00Z'),
    lastUpdated: new Date('2026-02-07T07:30:00Z'),
    confidenceScore: 90,
    riskScore: 92,
    blastRadius: 'extensive',
    exploitationLikelihood: 'imminent',
    description: 'Critical command injection vulnerability (CVSS 9.8) detected in Next.js route handler. Vulnerability is ACTIVELY EXPLOITED IN THE WILD per CISA KEV catalog and CISA Emergency Directive. Immediate patching required.',
    aiSummary: '🚨 CRITICAL SEVERITY: CVE-2024-3400 command injection vulnerability present in production Next.js application. CVSS 9.8 (Critical). CISA KEV Status: EXPLOITED. CISA Emergency Directive in effect. This vulnerability allows unauthenticated RCE. Attack vector aligns with T1190 (Exploit Public-Facing Application). SYSTEM COMPROMISE IMMINENT without immediate remediation.',
    rootCause: 'Unpatched Next.js installation (version < 14.2.0) with known remote code execution vulnerability in route handler processing.',
    attackVector: 'Specially crafted HTTP requests to Next.js route handlers (app/api/chat/route.ts) containing malicious payload',
    impact: 'Complete system compromise, remote code execution, data exfiltration, lateral movement, complete loss of confidentiality/integrity/availability',
    scope: 'All applications and data on affected server (app-server-01) and potentially connected systems',
    remediation: [
      'Upgrade Next.js to version 14.2.0 or later IMMEDIATELY - emergency patch deployment',
      'Deploy emergency WAF rules blocking known exploitation patterns within 15 minutes',
      'Conduct IOC (Indicator of Compromise) hunt on affected systems immediately',
      'Consider isolating app-server-01 from network pending patch verification',
      'Rotate all secrets and credentials on affected system post-patch',
      'Conduct penetration test to verify remediation effectiveness',
    ],
    containmentActions: [
      'Deploy WAF rule to block exploitation attempts - IMMEDIATE',
      'Enable enhanced logging on app/api/chat/route.ts',
      'Monitor for suspicious process execution on app-server-01',
      'Prepare emergency maintenance window for patch deployment',
    ],
    preventionMeasures: [
      'Implement automated vulnerability management with SLA-based patching',
      'Deploy runtime application self-protection (RASP) for input validation',
      'Implement defense-in-depth with multiple security layers',
      'Regular security assessments and penetration testing',
    ],
  },
  {
    id: 'INC-2026-0207-004',
    title: 'MEDIUM: Multiple Vulnerabilities in Authentication Flow',
    severity: 'medium',
    status: 'investigating',
    lifecycleState: 'Investigating',
    type: 'Security Control Weakness',
    affectedAssets: ['app/auth/callback/route.ts', 'app/api/auth/', 'app/api/messages/[id]/route.ts'],
    indicators: ['Open Redirect', 'Missing Rate Limiting', 'IDOR', 'SSRF potential'],
    mitreTechniques: ['T1190'],
    createdAt: new Date('2026-02-07T04:00:00Z'),
    lastUpdated: new Date('2026-02-07T07:00:00Z'),
    confidenceScore: 85,
    riskScore: 65,
    blastRadius: 'moderate',
    exploitationLikelihood: 'possible',
    description: 'Multiple security control weaknesses identified in authentication and authorization flows during security review. These vulnerabilities, while not currently exploited, significantly increase attack surface.',
    aiSummary: '🟡 MEDIUM SEVERITY: Multiple security control weaknesses identified in authentication infrastructure requiring remediation. Includes Open Redirect vulnerability enabling phishing, Missing Rate Limiting enabling brute force, and IDOR enabling unauthorized data access. Lower immediate risk but significant security debt.',
    rootCause: 'Inadequate security controls implemented during application development. Missing security review gates in CI/CD pipeline.',
    attackVector: 'Various - depends on specific vulnerability exploitation',
    impact: 'Increased phishing effectiveness, credential attack enablement, unauthorized data access',
    scope: 'Authentication and authorization subsystem',
    remediation: [
      'Implement Open Redirect fix with strict URL whitelist validation',
      'Deploy rate limiting on all auth endpoints per security policy',
      'Add ownership verification to all data access APIs',
      'Implement SSRF protections on auth callback handler',
      'Add comprehensive security headers to application responses',
    ],
    containmentActions: [
      'Deploy temporary WAF rules for Open Redirect and SSRF patterns',
      'Enable enhanced monitoring on auth callback endpoints',
    ],
    preventionMeasures: [
      'Add security code review requirements to development process',
      'Integrate SAST/DAST scanning into CI/CD pipeline',
      'Implement security gates blocking deployments with critical findings',
    ],
  },
];

// ============================================================================
// 8. COMPLIANCE VIOLATIONS
// ============================================================================

export interface ComplianceViolation {
  id: string;
  framework: string;
  controlId: string;
  title: string;
  severity: ThreatLevel;
  description: string;
  affectedArea: string;
  remediation: string;
  status: 'open' | 'remediated' | 'risk_accepted';
  dueDate?: Date;
}

export const complianceViolations: ComplianceViolation[] = [
  // SOC 2 Type II Violations
  {
    id: 'COMP-SOC2-001',
    framework: 'SOC 2 Type II',
    controlId: 'CC6.1',
    title: 'Logical Access Control Weakness',
    severity: 'high',
    description: 'Missing rate limiting on authentication endpoints violates logical access control requirements by enabling unlimited credential attacks.',
    affectedArea: 'Authentication System - app/api/auth/',
    remediation: 'Implement rate limiting with account lockout policies per CC6.1 requirements.',
    status: 'open',
    dueDate: new Date('2026-02-14'),
  },
  {
    id: 'COMP-SOC2-002',
    framework: 'SOC 2 Type II',
    controlId: 'CC6.6',
    title: 'Missing Security Headers',
    severity: 'medium',
    description: 'X-Frame-Options and X-Content-Type-Headers not configured, violating security header requirements.',
    affectedArea: 'Application Response Headers - app/layout.tsx',
    remediation: 'Add required security headers: X-Frame-Options, X-Content-Type-Options.',
    status: 'open',
    dueDate: new Date('2026-02-21'),
  },
  {
    id: 'COMP-SOC2-003',
    framework: 'SOC 2 Type II',
    controlId: 'CC7.2',
    title: 'System Monitoring Insufficient',
    severity: 'medium',
    description: 'Insufficient logging coverage on authentication events for security incident detection.',
    affectedArea: 'Audit Logging - auth-service',
    remediation: 'Enhance authentication logging to capture all login attempts, failures, and unusual activities.',
    status: 'open',
    dueDate: new Date('2026-02-28'),
  },
  // GDPR Violations
  {
    id: 'COMP-GDPR-001',
    framework: 'GDPR',
    controlId: 'Art. 32',
    title: 'Data Access Logging Insufficient',
    severity: 'medium',
    description: 'Data access logging does not meet Article 32 requirements for demonstrating data processing integrity.',
    affectedArea: 'Data Access Controls - Message API',
    remediation: 'Implement comprehensive audit logging for all data access operations including user and timestamp.',
    status: 'open',
    dueDate: new Date('2026-03-07'),
  },
  // ISO 27001 Violations
  {
    id: 'COMP-ISO27001-001',
    framework: 'ISO 27001',
    controlId: 'A.9.4.3',
    title: 'Password Policy Enforcement Weak',
    severity: 'high',
    description: 'Password policy enforcement not consistently applied across all authentication points.',
    affectedArea: 'Identity Management - Authentication System',
    remediation: 'Implement centralized password policy enforcement with complexity requirements and expiration.',
    status: 'open',
    dueDate: new Date('2026-02-14'),
  },
  {
    id: 'COMP-ISO27001-002',
    framework: 'ISO 27001',
    controlId: 'A.12.4.1',
    title: 'Logging and Monitoring Gaps',
    severity: 'medium',
    description: 'Security event logging does not cover all critical system components per A.12.4.1 requirements.',
    affectedArea: 'Security Monitoring - All Servers',
    remediation: 'Extend security logging coverage to include all authentication, authorization, and data access events.',
    status: 'open',
    dueDate: new Date('2026-02-28'),
  },
  {
    id: 'COMP-ISO27001-003',
    framework: 'ISO 27001',
    controlId: 'A.14.2.1',
    title: 'Secure Development Lifecycle Gaps',
    severity: 'medium',
    description: 'Security testing not integrated into development lifecycle allowing vulnerabilities to reach production.',
    affectedArea: 'SDLC - CI/CD Pipeline',
    remediation: 'Integrate automated security testing (SAST/DAST) into CI/CD pipeline with quality gates.',
    status: 'open',
    dueDate: new Date('2026-03-14'),
  },
  // PCI DSS Violations
  {
    id: 'COMP-PCI-001',
    framework: 'PCI DSS',
    controlId: 'Req. 8.2',
    title: 'Password Policy Enforcement Deficient',
    severity: 'high',
    description: 'Password policy not meeting PCI DSS Requirement 8.2 for credential complexity and expiration.',
    affectedArea: 'Authentication Controls',
    remediation: 'Implement PCI DSS compliant password requirements: minimum 7 characters, alphanumeric, expiration 90 days.',
    status: 'open',
    dueDate: new Date('2026-02-14'),
  },
  {
    id: 'COMP-PCI-002',
    framework: 'PCI DSS',
    controlId: 'Req. 6.4',
    title: 'Application Security Control Weaknesses',
    severity: 'medium',
    description: 'Multiple application security control weaknesses identified violating PCI DSS Requirement 6.4.',
    affectedArea: 'Application Security Controls',
    remediation: 'Implement comprehensive application security controls including input validation, output encoding, and secure coding practices.',
    status: 'open',
    dueDate: new Date('2026-02-21'),
  },
];

// ============================================================================
// 9. RISK ASSESSMENT SUMMARY
// ============================================================================

export interface RiskAssessment {
  overallRiskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  trend: 'improving' | 'stable' | 'degrading';
  keyRisks: {
    risk: string;
    impact: string;
    probability: string;
    mitigation: string;
  }[];
  recommendations: SecurityRecommendation[];
}

// ============================================================================
// 10. EXPORT SUMMARY
// ============================================================================

export interface ScanExportSummary {
  scanId: string;
  timestamp: Date;
  duration: string;
  assetsScanned: number;
  vulnerabilitiesFound: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  incidentsActive: number;
  complianceScore: number;
  securityScore: number;
  topThreats: string[];
  immediateActions: string[];
}

export const scanExportSummary: ScanExportSummary = {
  scanId: 'SOC-SCAN-20260207-073600',
  timestamp: new Date('2026-02-07T07:36:00Z'),
  duration: '12 minutes 34 seconds',
  assetsScanned: 3,
  vulnerabilitiesFound: 7,
  criticalCount: 2,
  highCount: 3,
  mediumCount: 2,
  lowCount: 1,
  incidentsActive: 4,
  complianceScore: 68,
  securityScore: 62,
  topThreats: [
    'CVE-2024-3400 Command Injection - Actively Exploited',
    'Brute Force Attack from Botnet IP 91.207.174.23',
    'Credential Attack on Analyst Account',
    'Multiple Authentication Control Weaknesses',
  ],
  immediateActions: [
    'BLOCK IP 91.207.174.23 at perimeter firewall',
    'Upgrade Next.js to 14.2.0+ to patch CVE-2024-3400',
    'Implement rate limiting on all auth endpoints',
    'Enable MFA for all privileged accounts',
    'Deploy WAF rules for exploitation pattern blocking',
    'Verify no successful authentications from threat IPs',
  ],
};
