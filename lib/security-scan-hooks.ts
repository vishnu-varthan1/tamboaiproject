// ============ TAMBO AI SECURITY SCAN HOOKS ============
// React hooks for AI-powered security scanning via Tambo API

import { useState, useCallback } from 'react';

interface ScanOptions {
  scanType: 'vulnerability' | 'compliance' | 'full';
  target?: string;
  includeCVE?: boolean;
  includeMITRE?: boolean;
  includeCompliance?: boolean;
}

interface VulnerabilityFinding {
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

interface VulnerabilitySummary {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  open?: number;
  inProgress?: number;
  resolved?: number;
}

interface SecurityReport {
  scanId: string;
  timestamp: string;
  scanType: string;
  duration: string;
  riskScore: number;
  riskLevel?: string;
  securityScore?: number;
  vulnerabilities?: VulnerabilitySummary;
  vulnerabilitiesList?: VulnerabilityFinding[];
  complianceStatus?: {
    framework: string;
    score: number;
    passed?: number;
    failed?: number;
  };
  mitreTechniques?: Array<{
    id: string;
    name: string;
    tactic: string;
    detections?: number;
    confidence?: number;
  }>;
  recommendations?: string[];
  aiSummary?: string;
  criticalFindings?: VulnerabilityFinding[];
}

interface UseSecurityScanReturn {
  scan: ScanOptions | null;
  report: SecurityReport | null;
  isScanning: boolean;
  error: string | null;
  startScan: (options: ScanOptions) => Promise<void>;
  resetScan: () => void;
}

export function useSecurityScan(): UseSecurityScanReturn {
  const [scan, setScan] = useState<ScanOptions | null>(null);
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const startScan = useCallback(async (options: ScanOptions) => {
    setIsScanning(true);
    setError(null);
    setScan(options);

    try {
      const response = await fetch('/api/security-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(options),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Security scan failed');
      }

      const data = await response.json();
      setReport(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred');
      console.error('Security scan error:', err);
    } finally {
      setIsScanning(false);
    }
  }, []);

  const resetScan = useCallback(() => {
    setScan(null);
    setReport(null);
    setError(null);
    setIsScanning(false);
  }, []);

  return {
    scan,
    report,
    isScanning,
    error,
    startScan,
    resetScan,
  };
}

// ============ TAMBO AI THREAT INTEL HOOK ============

interface ThreatIntelQuery {
  indicator: string;
  sources?: string[];
}

interface ThreatIntelResult {
  indicator: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  tags: string[];
  description: string;
  firstSeen?: string;
  lastSeen?: string;
}

interface UseThreatIntelReturn {
  results: ThreatIntelResult[];
  isQuerying: boolean;
  error: string | null;
  queryThreatIntel: (query: ThreatIntelQuery) => Promise<void>;
  clearResults: () => void;
}

export function useThreatIntel(): UseThreatIntelReturn {
  const [results, setResults] = useState<ThreatIntelResult[]>([]);
  const [isQuerying, setIsQuerying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const queryThreatIntel = useCallback(async (query: ThreatIntelQuery) => {
    setIsQuerying(true);
    setError(null);

    try {
      // In a real implementation, this would call the threat intel API
      // For now, we'll simulate with mock data
      const mockResults: ThreatIntelResult[] = [
        {
          indicator: query.indicator,
          type: 'IP',
          severity: 'high',
          confidence: 75,
          tags: ['suspicious', 'scanner'],
          description: 'Suspicious activity detected from this indicator',
          lastSeen: new Date().toISOString(),
        },
      ];
      setResults(mockResults);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Threat intel query failed');
    } finally {
      setIsQuerying(false);
    }
  }, []);

  const clearResults = useCallback(() => {
    setResults([]);
    setError(null);
  }, []);

  return {
    results,
    isQuerying,
    error,
    queryThreatIntel,
    clearResults,
  };
}

// ============ TAMBO AI MITRE ATT&CK HOOK ============

interface MitreMappingResult {
  vulnerabilityType: string;
  techniques: {
    id: string;
    name: string;
    tactic: string;
    description: string;
  }[];
}

interface UseMitreMappingReturn {
  mappings: MitreMappingResult | null;
  isMapping: boolean;
  error: string | null;
  getMappings: (vulnerabilityType: string) => Promise<void>;
  clearMappings: () => void;
}

export function useMitreMapping(): UseMitreMappingReturn {
  const [mappings, setMappings] = useState<MitreMappingResult | null>(null);
  const [isMapping, setIsMapping] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getMappings = useCallback(async (vulnerabilityType: string) => {
    setIsMapping(true);
    setError(null);

    try {
      // In a real implementation, this would call the MITRE ATT&CK API
      // For now, we'll return mock mappings based on vulnerability type
      const mockMappings: MitreMappingResult = {
        vulnerabilityType,
        techniques: [
          {
            id: 'T1190',
            name: 'Exploit Public-Facing Application',
            tactic: 'initial_access',
            description: 'Adversaries may attempt to exploit web applications to gain initial access',
          },
          {
            id: 'T1059',
            name: 'Command and Scripting Interpreter',
            tactic: 'execution',
            description: 'Adversaries may abuse command and script interpreters to execute commands',
          },
        ],
      };
      setMappings(mockMappings);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'MITRE mapping failed');
    } finally {
      setIsMapping(false);
    }
  }, []);

  const clearMappings = useCallback(() => {
    setMappings(null);
    setError(null);
  }, []);

  return {
    mappings,
    isMapping,
    error,
    getMappings,
    clearMappings,
  };
}

// ============ COMPLIANCE ASSESSMENT HOOK ============

interface ComplianceQuery {
  framework: 'SOC2' | 'ISO27001' | 'GDPR' | 'PCI DSS' | 'all';
  scope: string;
}

interface ComplianceResult {
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

interface UseComplianceAssessmentReturn {
  assessment: ComplianceResult | null;
  isAssessing: boolean;
  error: string | null;
  runAssessment: (query: ComplianceQuery) => Promise<void>;
  clearAssessment: () => void;
}

export function useComplianceAssessment(): UseComplianceAssessmentReturn {
  const [assessment, setAssessment] = useState<ComplianceResult | null>(null);
  const [isAssessing, setIsAssessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runAssessment = useCallback(async (query: ComplianceQuery) => {
    setIsAssessing(true);
    setError(null);

    try {
      // In a real implementation, this would call the compliance API
      const mockAssessment: ComplianceResult = {
        framework: query.framework,
        score: 68,
        controlsTotal: 12,
        controlsPassed: 8,
        controlsFailed: 4,
        failedControls: [
          {
            id: 'CC6.1',
            title: 'Logical Access Control Weakness',
            severity: 'high',
            description: 'Missing rate limiting on authentication endpoints',
          },
        ],
      };
      setAssessment(mockAssessment);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Compliance assessment failed');
    } finally {
      setIsAssessing(false);
    }
  }, []);

  const clearAssessment = useCallback(() => {
    setAssessment(null);
    setError(null);
  }, []);

  return {
    assessment,
    isAssessing,
    error,
    runAssessment,
    clearAssessment,
  };
}
