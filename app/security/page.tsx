'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { TamboProvider } from '@tambo-ai/react';
import { tamboComponents } from '@/app/components/tambo/TamboComponents';
import Sidebar from '../components/cybersecurity-dashboard/Sidebar';
import {
  SecurityMetrics,
  Vulnerability as SecurityVulnerability,
  SecurityIncident,
  SecurityAlert,
  ComplianceFramework,
  THREAT_LEVELS,
  VULNERABILITY_COLORS,
  ASSET_ICONS,
  INCIDENT_TYPES,
} from '@/lib/cybersecurity-types';
import { Threat, RiskScore, SecurityRecommendation, MITRE_TACTICS } from '@/lib/security-types';
import { analyzeSecurity, calculateRiskScore, getRecommendations } from '@/lib/security-analysis';
import { useSecurityScan } from '@/lib/security-scan-hooks';

// =====================================================
// TAMBO AI SOC DASHBOARD TYPES
// =====================================================

interface AIVulnerability {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  cvss?: number;
  cve?: string;
  affectedComponent: string;
  remediation: string;
  confidence: number;
}

interface AIIncident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'investigating' | 'contained' | 'resolved';
  type: string;
  confidenceScore: number;
  aiSummary: string;
  remediation: string[];
  mitreTechniques: string[];
  affectedAssets: string[];
}

interface AIComplianceResult {
  framework: string;
  score: number;
  controlsTotal: number;
  controlsPassed: number;
  controlsFailed: number;
  failedControls: {
    id: string;
    title: string;
    severity: string;
    description: string;
  }[];
}

interface AIReport {
  scanId: string;
  timestamp: string;
  duration: string;
  scanType: string;
  timeRange: string;
  securityScore: number;
  securityScoreTrend: number;
  riskLevel: string;
  vulnerabilities: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    open: number;
    inProgress: number;
    resolved: number;
  };
  vulnerabilitiesList?: AIVulnerability[];
  incidents: {
    total: number;
    critical: number;
    high: number;
    active: number;
    new: number;
    investigating: number;
  };
  compliance?: {
    overallScore: number;
    frameworks: ComplianceFramework[];
  };
  mitreTechniques?: Array<{
    id: string;
    name: string;
    tactic: string;
    detections?: number;
  }>;
  threatIntel?: {
    activeIOCs: number;
    criticalThreats: number;
  };
  assets?: Asset[];
  criticalFindings?: CriticalFinding[];
  aiSummary: string;
  scanHealth?: {
    status: string;
    message: string;
  };
}

interface Asset {
  id: string;
  name: string;
  type: string;
  ip: string;
  status: string;
  riskLevel: string;
  vulnerabilities: number;
  lastScan: number;
}

interface CriticalFinding {
  id: string;
  title: string;
  severity: string;
  cvss?: number | null;
  asset: string;
  status: string;
}

// Sample data for the dashboard
const sampleVulnerabilities = [
  {
    id: 'vuln-1',
    cve: 'CVE-2024-3400',
    title: 'Command Injection in Next.js API Route',
    severity: 'critical' as const,
    cvss: 9.8,
    affectedComponent: 'app-server-01',
    remediation: 'Update Next.js to version 14.2.0 or later',
    status: 'open',
    discoveredAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
  },
  {
    id: 'vuln-2',
    cve: 'CVE-2024-2739',
    title: 'SQL Injection in Authentication Module',
    severity: 'critical' as const,
    cvss: 9.1,
    affectedComponent: 'auth-service',
    remediation: 'Implement parameterized queries and input validation',
    status: 'open',
    discoveredAt: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString() // 4 hours ago
  },
  {
    id: 'vuln-3',
    cve: 'CVE-2024-2389',
    title: 'Privilege Escalation in User Service',
    severity: 'high' as const,
    cvss: 8.5,
    affectedComponent: 'user-service',
    remediation: 'Review and restrict user permission assignments',
    status: 'in-progress',
    discoveredAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() // 1 day ago
  },
  {
    id: 'vuln-4',
    cve: 'CVE-2024-1234',
    title: 'Cross-Site Scripting in Dashboard',
    severity: 'high' as const,
    cvss: 7.5,
    affectedComponent: 'web-dashboard',
    remediation: 'Implement proper output encoding and CSP headers',
    status: 'open',
    discoveredAt: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString() // 2 days ago
  },
  {
    id: 'vuln-5',
    cve: 'CVE-2024-5678',
    title: 'Insecure Deserialization in API',
    severity: 'medium' as const,
    cvss: 6.3,
    affectedComponent: 'api-gateway',
    remediation: 'Use secure deserialization libraries and validate input',
    status: 'open',
    discoveredAt: new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString() // 3 days ago
  },
];

const sampleIncidents = [
  {
    id: 'inc-1',
    title: 'Active Brute Force Attack Detected',
    severity: 'critical' as const,
    status: 'investigating' as const,
    type: 'Attack',
    affectedAssets: ['auth-service', 'login-server'],
    mitreTechniques: ['T1110 - Brute Force', 'T1078 - Valid Accounts'],
    detectedAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(), // 30 mins ago
    aiSummary: 'Multiple failed login attempts from suspicious IP addresses targeting the authentication service. Attack pattern suggests automated brute force tool.'
  },
  {
    id: 'inc-2',
    title: 'Data Exfiltration Attempt',
    severity: 'critical' as const,
    status: 'new' as const,
    type: 'Data Breach',
    affectedAssets: ['db-server-01', 'file-storage'],
    mitreTechniques: ['T1041 - Exfiltration Over C2', 'T1567 - Exfiltration Over Web Service'],
    detectedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 1 hour ago
    aiSummary: 'Abnormal data transfer patterns detected from database server to external IP. Immediate investigation required.'
  },
  {
    id: 'inc-3',
    title: 'Malware Detection on Workstation',
    severity: 'high' as const,
    status: 'contained' as const,
    type: 'Malware',
    affectedAssets: ['workstation-hr-15'],
    mitreTechniques: ['T1204 - User Execution', 'T1566 - Phishing'],
    detectedAt: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(), // 3 hours ago
    aiSummary: 'Trojan malware detected and isolated on HR workstation. Email attachment identified as infection vector.'
  },
  {
    id: 'inc-4',
    title: 'Unauthorized Access Attempt',
    severity: 'high' as const,
    status: 'investigating' as const,
    type: 'Unauthorized Access',
    affectedAssets: ['admin-panel', 'git-server'],
    mitreTechniques: ['T1078 - Valid Accounts', 'T1133 - External Remote Services'],
    detectedAt: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(), // 6 hours ago
    aiSummary: 'Multiple failed authentication attempts to admin panel from unknown IP range. Two-factor authentication blocked access.'
  },
  {
    id: 'inc-5',
    title: 'DDoS Attack Mitigation',
    severity: 'medium' as const,
    status: 'resolved' as const,
    type: 'DDoS',
    affectedAssets: ['web-server-01', 'load-balancer'],
    mitreTechniques: ['T1498 - Network Denial of Service'],
    detectedAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // 1 day ago
    aiSummary: 'Volumetric DDoS attack detected and mitigated by cloud protection. No service disruption experienced.'
  },
];

const sampleCompliance = {
  overallScore: 68,
  frameworks: [
    {
      name: 'SOC 2',
      score: 72,
      controlsPassed: 18,
      controlsFailed: 7,
      status: 'Non-Compliant'
    },
    {
      name: 'ISO 27001',
      score: 65,
      controlsPassed: 52,
      controlsFailed: 28,
      status: 'Non-Compliant'
    },
    {
      name: 'GDPR',
      score: 58,
      controlsPassed: 14,
      controlsFailed: 10,
      status: 'Non-Compliant'
    },
    {
      name: 'HIPAA',
      score: 75,
      controlsPassed: 45,
      controlsFailed: 15,
      status: 'Partial'
    }
  ],
  failedControls: [
    {
      id: 'AC-1',
      title: 'Access Control Policy',
      severity: 'high',
      description: 'Access control policy not documented and implemented for all systems'
    },
    {
      id: 'AU-2',
      title: 'Audit Events',
      severity: 'medium',
      description: 'Audit logging not enabled for critical database systems'
    },
    {
      id: 'SI-2',
      title: 'Flaw Remediation',
      severity: 'high',
      description: 'Critical vulnerabilities not remediated within required timeframe'
    }
  ]
};

const sampleAssets = [
  {
    id: 'asset-1',
    name: 'app-server-01',
    type: 'Server',
    ip: '10.0.1.10',
    status: 'active',
    riskLevel: 'critical',
    vulnerabilities: 3,
    lastScan: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
  },
  {
    id: 'asset-2',
    name: 'auth-service',
    type: 'Service',
    ip: '10.0.1.20',
    status: 'active',
    riskLevel: 'high',
    vulnerabilities: 2,
    lastScan: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
  },
  {
    id: 'asset-3',
    name: 'db-server-01',
    type: 'Database',
    ip: '10.0.2.10',
    status: 'active',
    riskLevel: 'high',
    vulnerabilities: 1,
    lastScan: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
  },
  {
    id: 'asset-4',
    name: 'web-dashboard',
    type: 'Application',
    ip: '10.0.1.30',
    status: 'active',
    riskLevel: 'medium',
    vulnerabilities: 2,
    lastScan: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
  },
  {
    id: 'asset-5',
    name: 'file-storage',
    type: 'Storage',
    ip: '10.0.3.10',
    status: 'active',
    riskLevel: 'low',
    vulnerabilities: 0,
    lastScan: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() // 2 hours ago
  },
  {
    id: 'asset-6',
    name: 'workstation-hr-15',
    type: 'Workstation',
    ip: '10.0.10.45',
    status: 'isolated',
    riskLevel: 'critical',
    vulnerabilities: 1,
    lastScan: Date.now() - 4 * 60 * 60 * 1000 // 4 hours ago
  },
];

// Helper function to format relative time
function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;
  
  const minutes = Math.floor(diff / (1000 * 60));
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes} min ago`;
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;
  
  return new Date(timestamp).toLocaleDateString();
}

// Helper function to format date for display
function formatDateTime(timestamp: number): string {
  return new Date(timestamp).toLocaleString();
}

// =====================================================
// DASHBOARD CONTENT COMPONENT
// =====================================================

function SecurityDashboardContent() {
  // Tambo AI Scanning State
  const [scanType, setScanType] = useState<'vulnerability' | 'compliance' | 'full'>('full');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [aiReport, setAiReport] = useState<AIReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Dashboard State
  const [activeTab, setActiveTab] = useState<'overview' | 'vulnerabilities' | 'incidents' | 'compliance' | 'assets' | 'ai-scan'>('overview');
  const [selectedTimeRange, setSelectedTimeRange] = useState<'24h' | '7d' | '30d' | '90d'>('7d');

  // AI Hooks for Real-time Scanning
  const { 
    report: scanReport, 
    isScanning: isHookScanning, 
    error: scanHookError,
    startScan: runAISCAN,
    resetScan: resetScanReport 
  } = useSecurityScan();

  // =====================================================
  // TAMBO AI SCANNING FUNCTIONS
  // =====================================================

  const startTamboScan = async (type: 'vulnerability' | 'compliance' | 'full') => {
    setIsScanning(true);
    setScanProgress(0);
    setScanError(null);

    // Simulate progress
    const progressInterval = setInterval(() => {
      setScanProgress(prev => Math.min(prev + 10, 95));
    }, 500);

    try {
      const response = await fetch('/api/security-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scanType: type,
          target: 'full-scope',
          options: {
            includeCVE: true,
            includeMITRE: true,
            includeCompliance: true,
          },
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'AI scan failed');
      }

      const data = await response.json();
      setAiReport(data);
      setScanProgress(100);
    } catch (err) {
      setScanError(err instanceof Error ? err.message : 'Unknown error');
      console.error('Tambo AI Scan error:', err);
    } finally {
      clearInterval(progressInterval);
      setIsScanning(false);
    }
  };

  const resetTamboScan = () => {
    setAiReport(null);
    setScanError(null);
    setScanProgress(0);
    resetScanReport();
  };

  // =====================================================
  // RENDER OVERVIEW TAB
  // =====================================================

  const renderOverview = () => (
    <div className="space-y-6">
      {/* AI Scan Status Banner */}
      {isScanning && (
        <div className="bg-gradient-to-r from-blue-900/50 to-purple-900/50 border border-blue-500/30 rounded-xl p-4">
          <div className="flex items-center gap-4">
            <div className="animate-spin text-2xl">🔄</div>
            <div className="flex-1">
              <p className="text-white font-semibold">AI Scan in Progress</p>
              <p className="text-gray-400 text-sm">Analyzing codebase for vulnerabilities, compliance gaps, and threats</p>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-blue-400">{scanProgress}%</p>
              <p className="text-gray-400 text-xs">Complete</p>
            </div>
          </div>
          <div className="mt-4 h-2 bg-gray-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-300"
              style={{ width: `${scanProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Scan Error Banner */}
      {scanError && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <span className="text-xl">❌</span>
            <p className="text-red-400">{scanError}</p>
            <button 
              onClick={() => setScanError(null)}
              className="ml-auto px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-sm rounded-lg transition-colors"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* SecOps Alert Badge */}
      <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-xl">⚠️</span>
          <span className="text-white font-medium">SecOps Alert</span>
        </div>
        <span className="bg-red-500 text-white text-sm font-bold px-3 py-1 rounded-full">2</span>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Security Score</p>
              <p className="text-2xl font-bold text-white mt-1">{aiReport?.securityScore || 62}</p>
              <p className="text-red-400 text-xs mt-1">↓ 5 from last scan</p>
            </div>
            <span className="text-3xl">🎯</span>
          </div>
        </div>

        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Incidents</p>
              <p className="text-2xl font-bold text-white mt-1">{aiReport?.incidents.total || 4}</p>
              <p className="text-red-400 text-xs mt-1">2 Critical</p>
            </div>
            <span className="text-3xl">🚨</span>
          </div>
        </div>

        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Vulnerabilities</p>
              <p className="text-2xl font-bold text-white mt-1">{aiReport?.vulnerabilities.total || 7}</p>
              <p className="text-red-400 text-xs mt-1">2 Critical</p>
            </div>
            <span className="text-3xl">🔓</span>
          </div>
        </div>

        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Compliance Score</p>
              <p className="text-2xl font-bold text-white mt-1">{aiReport?.compliance?.overallScore || 68}%</p>
              <p className="text-yellow-400 text-xs mt-1">4 Controls Failed</p>
            </div>
            <span className="text-3xl">📋</span>
          </div>
        </div>
      </div>

      {/* Vulnerability Distribution */}
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
        <h3 className="text-white font-semibold mb-4">Vulnerability Distribution</h3>
        <div className="space-y-3">
          {[
            { label: 'Critical', count: aiReport?.vulnerabilities.critical || 2, color: '#ef4444', percentage: 28 },
            { label: 'High', count: aiReport?.vulnerabilities.high || 3, color: '#f97316', percentage: 43 },
            { label: 'Medium', count: aiReport?.vulnerabilities.medium || 2, color: '#eab308', percentage: 29 },
            { label: 'Low', count: aiReport?.vulnerabilities.low || 1, color: '#22c55e', percentage: 14 },
          ].map((item) => (
            <div key={item.label} className="flex items-center gap-4">
              <div className="w-20">
                <span className="text-gray-400 text-sm">{item.label}</span>
              </div>
              <div className="flex-1">
                <div className="h-4 bg-[#0d0d0d] rounded-full overflow-hidden">
                  <div 
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${item.percentage}%`, backgroundColor: item.color }}
                  />
                </div>
              </div>
              <div className="w-12 text-right">
                <span className="text-white font-medium">{item.count}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Critical Findings */}
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
        <h3 className="text-white font-semibold mb-4">Critical Findings Requiring Immediate Attention</h3>
        <div className="space-y-3">
          {sampleVulnerabilities.slice(0, 2).map((finding, i) => (
            <div key={i} className="bg-[#0d0d0d] rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    finding.severity === 'critical' 
                      ? 'bg-red-500/20 text-red-400' 
                      : 'bg-orange-500/20 text-orange-400'
                  }`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  {finding.cvss && (
                    <span className="text-gray-400 text-xs">CVSS {finding.cvss}</span>
                  )}
                </div>
                <span className="text-gray-400 text-xs capitalize">{finding.status}</span>
              </div>
              <p className="text-white font-medium mb-1">{finding.cve}: {finding.title}</p>
              <p className="text-gray-400 text-sm">Affected: {finding.affectedComponent}</p>
              <div className="flex gap-2 mt-3">
                <button 
                  onClick={() => setActiveTab('vulnerabilities')}
                  className="px-3 py-1 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-xs rounded-lg transition-colors"
                >
                  Investigate
                </button>
                <button className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 text-xs rounded-lg transition-colors">
                  View Details
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Incidents */}
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold">Recent Security Incidents</h3>
          <button 
            onClick={() => setActiveTab('incidents')}
            className="text-[#10a37f] hover:text-[#0d8a6a] text-sm"
          >
            View All →
          </button>
        </div>
        <div className="space-y-3">
          {sampleIncidents.slice(0, 3).map((incident, i) => (
            <div key={i} className="bg-[#0d0d0d] rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    incident.severity === 'critical' 
                      ? 'bg-red-500/20 text-red-400' 
                      : incident.severity === 'high'
                      ? 'bg-orange-500/20 text-orange-400'
                      : 'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {incident.severity.toUpperCase()}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-xs ${
                    incident.status === 'investigating'
                      ? 'bg-blue-500/20 text-blue-400'
                      : incident.status === 'new'
                      ? 'bg-purple-500/20 text-purple-400'
                      : incident.status === 'contained'
                      ? 'bg-orange-500/20 text-orange-400'
                      : 'bg-green-500/20 text-green-400'
                  }`}>
                    {incident.status}
                  </span>
                </div>
                <span className="text-gray-400 text-xs">
                  {formatRelativeTime(incident.detectedAt)}
                </span>
              </div>
              <p className="text-white font-medium mb-1">{incident.title}</p>
              <p className="text-gray-400 text-sm">Type: {incident.type}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // =====================================================
  // RENDER VULNERABILITIES TAB
  // =====================================================

  const renderVulnerabilities = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Vulnerability Management</h2>
          <p className="text-gray-400 text-sm">Track and manage security vulnerabilities across your infrastructure</p>
        </div>
        <button
          onClick={() => startTamboScan('vulnerability')}
          disabled={isScanning}
          className="px-4 py-2 bg-[#10a37f] hover:bg-[#0d8a6a] text-white font-medium rounded-lg transition-colors flex items-center gap-2"
        >
          <span>🔍</span>
          Run Scan
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-white">{sampleVulnerabilities.length}</p>
          <p className="text-gray-400 text-sm">Total</p>
        </div>
        <div className="bg-[#1a1a2e] border border-red-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-red-400">{sampleVulnerabilities.filter(v => v.severity === 'critical').length}</p>
          <p className="text-gray-400 text-sm">Critical</p>
        </div>
        <div className="bg-[#1a1a2e] border border-orange-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-orange-400">{sampleVulnerabilities.filter(v => v.severity === 'high').length}</p>
          <p className="text-gray-400 text-sm">High</p>
        </div>
        <div className="bg-[#1a1a2e] border border-yellow-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-yellow-400">{sampleVulnerabilities.filter(v => v.severity === 'medium').length}</p>
          <p className="text-gray-400 text-sm">Medium</p>
        </div>
        <div className="bg-[#1a1a2e] border border-green-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-green-400">0</p>
          <p className="text-gray-400 text-sm">Resolved</p>
        </div>
      </div>

      {/* Vulnerability List */}
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-[#0d0d0d]">
              <tr>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">CVE</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Title</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Severity</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">CVSS</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Affected</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Status</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sampleVulnerabilities.map((vuln, i) => (
                <tr key={vuln.id} className="border-t border-[#2a2a4e] hover:bg-[#0d0d0d] transition-colors">
                  <td className="p-4">
                    <span className="text-[#10a37f] font-mono text-sm">{vuln.cve}</span>
                  </td>
                  <td className="p-4">
                    <p className="text-white font-medium">{vuln.title}</p>
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      vuln.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      vuln.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      vuln.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {vuln.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="p-4">
                    <span className={`font-mono ${
                      vuln.cvss >= 9 ? 'text-red-400' :
                      vuln.cvss >= 7 ? 'text-orange-400' :
                      vuln.cvss >= 4 ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {vuln.cvss}
                    </span>
                  </td>
                  <td className="p-4">
                    <span className="text-gray-300 text-sm">{vuln.affectedComponent}</span>
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      vuln.status === 'open' ? 'bg-red-500/20 text-red-400' :
                      vuln.status === 'in-progress' ? 'bg-blue-500/20 text-blue-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {vuln.status}
                    </span>
                  </td>
                  <td className="p-4">
                    <div className="flex gap-2">
                      <button className="px-3 py-1 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-xs rounded-lg transition-colors">
                        Details
                      </button>
                      <button className="px-3 py-1 bg-[#10a37f]/20 hover:bg-[#10a37f]/30 text-[#10a37f] text-xs rounded-lg transition-colors">
                        Remediate
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  // =====================================================
  // RENDER INCIDENTS TAB
  // =====================================================

  const renderIncidents = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Incident Response</h2>
          <p className="text-gray-400 text-sm">Monitor and manage security incidents in real-time</p>
        </div>
        <div className="flex gap-2">
          <select 
            className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-lg px-4 py-2 text-white text-sm"
            aria-label="Filter by severity"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High & Above</option>
          </select>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-white">{sampleIncidents.length}</p>
          <p className="text-gray-400 text-sm">Total Incidents</p>
        </div>
        <div className="bg-[#1a1a2e] border border-red-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-red-400">{sampleIncidents.filter(i => i.severity === 'critical').length}</p>
          <p className="text-gray-400 text-sm">Critical</p>
        </div>
        <div className="bg-[#1a1a2e] border border-blue-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-blue-400">{sampleIncidents.filter(i => i.status === 'investigating').length}</p>
          <p className="text-gray-400 text-sm">Investigating</p>
        </div>
        <div className="bg-[#1a1a2e] border border-green-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-green-400">{sampleIncidents.filter(i => i.status === 'resolved').length}</p>
          <p className="text-gray-400 text-sm">Resolved</p>
        </div>
      </div>

      {/* Incident Cards */}
      <div className="space-y-4">
        {sampleIncidents.map((incident) => (
          <div key={incident.id} className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <span className={`px-3 py-1 rounded text-xs font-medium ${
                  incident.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                  incident.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-yellow-500/20 text-yellow-400'
                }`}>
                  {incident.severity.toUpperCase()}
                </span>
                <span className={`px-3 py-1 rounded text-xs ${
                  incident.status === 'investigating' ? 'bg-blue-500/20 text-blue-400' :
                  incident.status === 'new' ? 'bg-purple-500/20 text-purple-400' :
                  incident.status === 'contained' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-green-500/20 text-green-400'
                }`}>
                  {incident.status.toUpperCase().replace('_', ' ')}
                </span>
                <span className="text-gray-400 text-sm">
                  {new Date(incident.detectedAt).toLocaleString()}
                </span>
              </div>
              <button className="px-3 py-1 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-xs rounded-lg transition-colors">
                View Details
              </button>
            </div>

            <h3 className="text-lg font-semibold text-white mb-2">{incident.title}</h3>
            <p className="text-gray-300 text-sm mb-4">{incident.aiSummary}</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-gray-400 text-xs mb-1">Affected Assets</p>
                <div className="flex flex-wrap gap-2">
                  {incident.affectedAssets.map((asset, i) => (
                    <span key={i} className="px-2 py-0.5 bg-[#0d0d0d] rounded text-xs text-gray-300">
                      {asset}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-gray-400 text-xs mb-1">MITRE ATT&CK Techniques</p>
                <div className="flex flex-wrap gap-2">
                  {incident.mitreTechniques.map((technique, i) => (
                    <span key={i} className="px-2 py-0.5 bg-[#0d0d0d] rounded text-xs text-[#10a37f] font-mono">
                      {technique}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex gap-2 pt-4 border-t border-[#2a2a4e]">
              <button className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 text-sm rounded-lg transition-colors">
                Escalate
              </button>
              <button className="px-4 py-2 bg-[#10a37f]/20 hover:bg-[#10a37f]/30 text-[#10a37f] text-sm rounded-lg transition-colors">
                Update Status
              </button>
              <button className="px-4 py-2 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-sm rounded-lg transition-colors">
                Add Notes
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  // =====================================================
  // RENDER COMPLIANCE TAB
  // =====================================================

  const renderCompliance = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Compliance Management</h2>
          <p className="text-gray-400 text-sm">Track compliance with security frameworks and regulations</p>
        </div>
        <button
          onClick={() => startTamboScan('compliance')}
          disabled={isScanning}
          className="px-4 py-2 bg-[#10a37f] hover:bg-[#0d8a6a] text-white font-medium rounded-lg transition-colors flex items-center gap-2"
        >
          <span>📋</span>
          Run Assessment
        </button>
      </div>

      {/* Overall Score */}
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-white font-semibold">Overall Compliance Score</h3>
            <p className="text-gray-400 text-sm">Combined score across all frameworks</p>
          </div>
          <div className="text-right">
            <p className="text-4xl font-bold text-white">{sampleCompliance.overallScore}%</p>
            <p className="text-gray-400 text-sm">Non-Compliant</p>
          </div>
        </div>
        <div className="h-4 bg-[#0d0d0d] rounded-full overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500 transition-all duration-500"
            style={{ width: `${sampleCompliance.overallScore}%` }}
          />
        </div>
      </div>

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {sampleCompliance.frameworks.map((framework) => (
          <div key={framework.name} className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">{framework.name}</h3>
              <span className={`px-2 py-1 rounded text-xs font-medium ${
                framework.status === 'Compliant' ? 'bg-green-500/20 text-green-400' :
                framework.status === 'Partial' ? 'bg-yellow-500/20 text-yellow-400' :
                'bg-red-500/20 text-red-400'
              }`}>
                {framework.status}
              </span>
            </div>
            <div className="flex items-end gap-2 mb-4">
              <p className="text-3xl font-bold text-white">{framework.score}%</p>
              <p className="text-gray-400 text-sm mb-1">Score</p>
            </div>
            <div className="h-2 bg-[#0d0d0d] rounded-full overflow-hidden mb-4">
              <div 
                className={`h-full transition-all duration-500 ${
                  framework.score >= 80 ? 'bg-green-500' :
                  framework.score >= 60 ? 'bg-yellow-500' :
                  'bg-red-500'
                }`}
                style={{ width: `${framework.score}%` }}
              />
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-green-400">{framework.controlsPassed} Passed</span>
              <span className="text-red-400">{framework.controlsFailed} Failed</span>
            </div>
          </div>
        ))}
      </div>

      {/* Failed Controls */}
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-6">
        <h3 className="text-white font-semibold mb-4">Failed Controls Requiring Attention</h3>
        <div className="space-y-3">
          {sampleCompliance.failedControls.map((control) => (
            <div key={control.id} className="bg-[#0d0d0d] rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-[#10a37f] font-mono text-sm">{control.id}</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                    control.severity === 'high' ? 'bg-red-500/20 text-red-400' :
                    'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {control.severity.toUpperCase()}
                  </span>
                </div>
                <button className="px-3 py-1 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-xs rounded-lg transition-colors">
                  Create Ticket
                </button>
              </div>
              <p className="text-white font-medium">{control.title}</p>
              <p className="text-gray-400 text-sm mt-1">{control.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // =====================================================
  // RENDER ASSETS TAB
  // =====================================================

  const renderAssets = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Asset Management</h2>
          <p className="text-gray-400 text-sm">Inventory and security posture of all IT assets</p>
        </div>
        <div className="flex gap-2">
          <select 
            className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-lg px-4 py-2 text-white text-sm"
            aria-label="Filter by asset type"
          >
            <option value="all">All Types</option>
            <option value="server">Servers</option>
            <option value="workstation">Workstations</option>
            <option value="database">Databases</option>
          </select>
          <button className="px-4 py-2 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-sm rounded-lg transition-colors">
            Export
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-white">{sampleAssets.length}</p>
          <p className="text-gray-400 text-sm">Total Assets</p>
        </div>
        <div className="bg-[#1a1a2e] border border-green-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-green-400">{sampleAssets.filter(a => a.status === 'active').length}</p>
          <p className="text-gray-400 text-sm">Active</p>
        </div>
        <div className="bg-[#1a1a2e] border border-red-500/30 rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-red-400">{sampleAssets.filter(a => a.riskLevel === 'critical').length}</p>
          <p className="text-gray-400 text-sm">Critical Risk</p>
        </div>
        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4 text-center">
          <p className="text-3xl font-bold text-white">{sampleAssets.reduce((acc, a) => acc + a.vulnerabilities, 0)}</p>
          <p className="text-gray-400 text-sm">Total Vulnerabilities</p>
        </div>
      </div>

      {/* Asset Table */}
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-[#0d0d0d]">
              <tr>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Asset</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Type</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">IP Address</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Status</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Risk Level</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Vulnerabilities</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Last Scan</th>
                <th className="text-left p-4 text-gray-400 text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sampleAssets.map((asset) => (
                <tr key={asset.id} className="border-t border-[#2a2a4e] hover:bg-[#0d0d0d] transition-colors">
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <span className="text-lg">
                        {asset.type === 'Server' ? '🖥️' :
                         asset.type === 'Database' ? '🗄️' :
                         asset.type === 'Application' ? '📱' :
                         asset.type === 'Storage' ? '💾' :
                         '💻'}
                      </span>
                      <span className="text-white font-medium">{asset.name}</span>
                    </div>
                  </td>
                  <td className="p-4">
                    <span className="text-gray-300">{asset.type}</span>
                  </td>
                  <td className="p-4">
                    <span className="font-mono text-sm text-gray-300">{asset.ip}</span>
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      asset.status === 'active' ? 'bg-green-500/20 text-green-400' :
                      asset.status === 'isolated' ? 'bg-red-500/20 text-red-400' :
                      'bg-gray-500/20 text-gray-400'
                    }`}>
                      {asset.status}
                    </span>
                  </td>
                  <td className="p-4">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                      asset.riskLevel === 'critical' ? 'bg-red-500/20 text-red-400' :
                      asset.riskLevel === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      asset.riskLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>
                      {asset.riskLevel.toUpperCase()}
                    </span>
                  </td>
                  <td className="p-4">
                    <span className={`font-medium ${
                      asset.vulnerabilities >= 3 ? 'text-red-400' :
                      asset.vulnerabilities >= 2 ? 'text-orange-400' :
                      asset.vulnerabilities >= 1 ? 'text-yellow-400' :
                      'text-green-400'
                    }`}>
                      {asset.vulnerabilities}
                    </span>
                  </td>
                  <td className="p-4">
                    <span className="text-gray-400 text-sm">
                      {new Date(asset.lastScan).toLocaleDateString()}
                    </span>
                  </td>
                  <td className="p-4">
                    <button className="px-3 py-1 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-xs rounded-lg transition-colors">
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  // =====================================================
  // RENDER AI SCAN TAB
  // =====================================================

  const renderAIScan = () => (
    <div className="space-y-6">
      <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-6">
        <div className="flex items-center gap-3 mb-6">
          <span className="text-4xl">🤖</span>
          <div>
            <h2 className="text-xl font-bold text-white">AI Scan</h2>
            <p className="text-gray-400 text-sm">AI-driven threat detection, vulnerability analysis, and automated response for modern SecOps teams.</p>
          </div>
        </div>

        {/* Scan Options */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {[
            { 
              id: 'vulnerability', 
              label: 'Vulnerability Scan', 
              icon: '🔍', 
              desc: 'Detect CVEs and security flaws',
              color: 'blue'
            },
            { 
              id: 'compliance', 
              label: 'Compliance Check', 
              icon: '📋', 
              desc: 'SOC 2, ISO 27001, GDPR',
              color: 'green'
            },
            { 
              id: 'full', 
              label: 'Full Security Audit', 
              icon: '🎯', 
              desc: 'Comprehensive analysis',
              color: 'purple'
            },
          ].map((option) => (
            <button
              key={option.id}
              onClick={() => startTamboScan(option.id as 'vulnerability' | 'compliance' | 'full')}
              disabled={isScanning}
              className={`p-4 border rounded-xl transition-all text-left ${
                scanType === option.id
                  ? `border-${option.color}-500 bg-${option.color}-500/10`
                  : 'border-[#2a2a4e] hover:border-[#3a3a6e]'
              }`}
            >
              <div className="text-2xl mb-2">{option.icon}</div>
              <p className="text-white font-medium">{option.label}</p>
              <p className="text-gray-400 text-xs mt-1">{option.desc}</p>
            </button>
          ))}
        </div>

        {/* Scan Progress */}
        {isScanning && (
          <div className="bg-[#0d0d0d] rounded-xl p-6">
            <div className="flex items-center gap-4 mb-4">
              <div className="animate-spin text-2xl">🔄</div>
              <div>
                <p className="text-white font-medium">AI Analysis in Progress</p>
                <p className="text-gray-400 text-sm">Processing with EVS AI</p>
              </div>
            </div>
            <div className="h-3 bg-[#2a2a4e] rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-blue-500 to-purple-500 animate-pulse"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
            <p className="text-right text-gray-400 text-sm mt-2">{scanProgress}% Complete</p>
          </div>
        )}

        {/* Scan Button */}
        {!isScanning && !aiReport && (
          <button
            onClick={() => startTamboScan('full')}
            className="w-full py-4 bg-gradient-to-r from-[#10a37f] to-[#0d8a6a] hover:from-[#0d8a6a] hover:to-[#0a7a5f] text-white font-semibold rounded-xl transition-all flex items-center justify-center gap-2"
          >
            <span className="text-xl">🚀</span>
            Start AI Scan
          </button>
        )}
      </div>

      {/* Scan Results */}
      {aiReport && (
        <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <span className="text-4xl">✅</span>
              <div>
                <h3 className="text-xl font-bold text-white">Scan Complete</h3>
                <p className="text-gray-400 text-sm">Scan ID: {aiReport.scanId}</p>
              </div>
            </div>
            <button
              onClick={resetTamboScan}
              className="px-4 py-2 bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white text-sm rounded-lg transition-colors"
            >
              New Scan
            </button>
          </div>

          {/* AI Summary */}
          <div className="bg-[#0d0d0d] rounded-xl p-4 mb-6">
            <p className="text-white font-medium mb-2">AI Summary</p>
            <p className="text-gray-300 text-sm">{aiReport.aiSummary}</p>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-[#0d0d0d] rounded-xl p-4 text-center">
              <p className="text-3xl font-bold text-white">{aiReport.securityScore}</p>
              <p className="text-gray-400 text-sm">Security Score</p>
            </div>
            <div className="bg-[#0d0d0d] rounded-xl p-4 text-center">
              <p className="text-3xl font-bold text-red-400">{aiReport.vulnerabilities.critical}</p>
              <p className="text-gray-400 text-sm">Critical</p>
            </div>
            <div className="bg-[#0d0d0d] rounded-xl p-4 text-center">
              <p className="text-3xl font-bold text-orange-400">{aiReport.vulnerabilities.high}</p>
              <p className="text-gray-400 text-sm">High</p>
            </div>
            <div className="bg-[#0d0d0d] rounded-xl p-4 text-center">
              <p className="text-3xl font-bold text-yellow-400">{aiReport.incidents.total}</p>
              <p className="text-gray-400 text-sm">Incidents</p>
            </div>
          </div>

          {/* Risk Level */}
          <div className={`p-4 rounded-xl text-center mb-6 ${aiReport.riskLevel === 'CRITICAL' ? 'bg-red-500/20 border border-red-500/30' : aiReport.riskLevel === 'HIGH' ? 'bg-orange-500/20 border border-orange-500/30' : 'bg-green-500/20 border border-green-500/30'}`}>
            <p className="text-white font-bold text-xl">Risk Level: {aiReport.riskLevel}</p>
          </div>

          {/* Vulnerabilities */}
          {aiReport.vulnerabilitiesList && aiReport.vulnerabilitiesList.length > 0 && (
            <div className="mb-6">
              <h4 className="text-white font-semibold mb-3">Top Vulnerabilities</h4>
              <div className="space-y-3">
                {aiReport.vulnerabilitiesList.slice(0, 5).map((vuln) => (
                  <div key={vuln.id} className="bg-[#0d0d0d] rounded-xl p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        vuln.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        vuln.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        vuln.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {vuln.severity.toUpperCase()}
                      </span>
                      {vuln.cve && (
                        <span className="text-gray-400 text-xs">{vuln.cve}</span>
                      )}
                    </div>
                    <p className="text-white font-medium mb-1">{vuln.title}</p>
                    <p className="text-gray-400 text-sm mb-2">{vuln.affectedComponent}</p>
                    <p className="text-gray-300 text-sm">{vuln.remediation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Compliance */}
          <div>
            <h4 className="text-white font-semibold mb-3">Compliance Score</h4>
            <div className="bg-[#0d0d0d] rounded-xl p-4">
              <div className="flex items-center justify-between mb-4">
                <span className="text-white">Overall Score</span>
                <span className="text-2xl font-bold text-white">{aiReport.compliance?.overallScore || 0}%</span>
              </div>
              <div className="h-3 bg-[#2a2a4e] rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-red-500 to-green-500 transition-all duration-500"
                  style={{ width: `${aiReport.compliance?.overallScore || 0}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  // =====================================================
  // MAIN RENDER
  // =====================================================

  const tabs: { id: 'overview' | 'vulnerabilities' | 'incidents' | 'compliance' | 'assets' | 'ai-scan'; label: string; icon: string }[] = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🔓' },
    { id: 'incidents', label: 'Incidents', icon: '🚨' },
    { id: 'compliance', label: 'Compliance', icon: '📋' },
    { id: 'assets', label: 'Assets', icon: '🖥️' },
    { id: 'ai-scan', label: 'AI Scan', icon: '🤖' },
  ];

  return (
    <div className="min-h-screen bg-[#0d0d0d]">
      {/* Header */}
      <div className="bg-[#171717] border-b border-[#2a2a2a] px-4 py-3">
        <div className="max-w-full mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <div>
              <h1 className="text-lg font-semibold text-white">SecOps Dashboard</h1>
              <p className="text-xs text-gray-500">EVS — Security Operations Powered by Tambo AI</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="px-4 py-2 bg-[#1a1a2e] hover:bg-[#262626] border border-[#2a2a4e] text-white text-sm font-medium rounded-lg transition-colors flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
              AI Chat
            </Link>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="bg-[#171717] border-b border-[#2a2a2a] px-4">
        <div className="max-w-full mx-auto">
          <nav className="flex gap-1 overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'text-[#10a37f] border-b-2 border-[#10a37f]'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <span>{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main Content - Full Width */}
      <main className="max-w-full mx-auto px-4 py-6">
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'vulnerabilities' && renderVulnerabilities()}
        {activeTab === 'incidents' && renderIncidents()}
        {activeTab === 'compliance' && renderCompliance()}
        {activeTab === 'assets' && renderAssets()}
        {activeTab === 'ai-scan' && renderAIScan()}
      </main>
    </div>
  );
}

// =====================================================
// PAGE EXPORT
// =====================================================

export default function SecurityPage() {
  return (
    <TamboProvider
      apiKey={process.env.NEXT_PUBLIC_TAMBO_API_KEY || "demo-key"}
      components={tamboComponents}
    >
      <SecurityDashboardContent />
    </TamboProvider>
  );
}
