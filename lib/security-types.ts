// Cybersecurity SaaS Platform - Type Definitions

export type ThreatLevel = 'low' | 'medium' | 'high' | 'critical';

export type SecureMode = 'strict' | 'balanced' | 'research';

export type ChatCategory = 'general' | 'coding' | 'cybersecurity' | 'threat_analysis' | 'incident_response';

export type ModelType = 'secure' | 'advanced' | 'research';

export type ThreatType = 
  | 'prompt_injection'
  | 'malware_indicators'
  | 'phishing'
  | 'credential_leakage'
  | 'insecure_code'
  | 'data_exfiltration'
  | 'social_engineering'
  | 'unauthorized_access'
  | 'sql_injection'
  | 'xss'
  | 'csrf'
  | 'cryptographic_weakness';

export interface Threat {
  id: string;
  type: ThreatType;
  severity: ThreatLevel;
  title: string;
  description: string;
  confidence: number; // 0-100
  mitigations: string[];
  references?: string[];
}

export interface RiskScore {
  overall: number;
  breakdown: {
    promptInjection: number;
    dataPrivacy: number;
    codeSecurity: number;
    socialEngineering: number;
  };
}

export interface MitreAttack {
  id: string;
  name: string;
  tactic: MitreTactic;
  technique: string;
  description: string;
  detection: string;
}

export type MitreTactic = 
  | 'initial_access'
  | 'execution'
  | 'persistence'
  | 'privilege_escalation'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'lateral_movement'
  | 'collection'
  | 'exfiltration'
  | 'impact';

export interface Vulnerability {
  id: string;
  cve?: string;
  title: string;
  severity: ThreatLevel;
  cvss?: number;
  description: string;
  affectedComponent: string;
  remediation: string;
  status: 'open' | 'in_progress' | 'resolved' | 'accepted';
}

export interface SecurityRecommendation {
  id: string;
  priority: ThreatLevel;
  category: string;
  title: string;
  description: string;
  implementation: string[];
  estimatedEffort: 'low' | 'medium' | 'high';
}

export interface SecurityLog {
  id: string;
  timestamp: Date;
  eventType: string;
  severity: ThreatLevel;
  message: string;
  metadata?: Record<string, unknown>;
}

export interface MessageSecurityAnalysis {
  threatLevel: ThreatLevel;
  riskScore: RiskScore;
  threats: Threat[];
  mitreAttacks: MitreAttack[];
  vulnerabilities: Vulnerability[];
  recommendations: SecurityRecommendation[];
  isSafe: boolean;
  analysisTimestamp: Date;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  securityAnalysis?: MessageSecurityAnalysis;
  category?: ChatCategory;
  codeSnippets?: CodeSnippet[];
}

export interface CodeSnippet {
  language: string;
  code: string;
  securityIssues?: SecurityIssue[];
}

export interface SecurityIssue {
  line: number;
  severity: ThreatLevel;
  message: string;
  suggestion: string;
}

export interface Conversation {
  id: string;
  title: string;
  category: ChatCategory;
  createdAt: Date;
  updatedAt: Date;
  messageCount: number;
  lastMessage?: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  avatar?: string;
  organization?: string;
  role: 'admin' | 'analyst' | 'viewer';
}

// Security Constants
export const THREAT_LEVELS: Record<ThreatLevel, { color: string; label: string; score: number }> = {
  low: { color: 'var(--threat-low)', label: 'Low Risk', score: 25 },
  medium: { color: 'var(--threat-medium)', label: 'Medium Risk', score: 50 },
  high: { color: 'var(--threat-high)', label: 'High Risk', score: 75 },
  critical: { color: 'var(--threat-critical)', label: 'Critical Risk', score: 100 },
};

export const MITRE_TACTICS: Record<MitreTactic, { color: string; icon: string }> = {
  initial_access: { color: 'var(--mitre-initial)', icon: '🚪' },
  execution: { color: 'var(--mitre-execution)', icon: '⚡' },
  persistence: { color: 'var(--mitre-persistence)', icon: '🔄' },
  privilege_escalation: { color: 'var(--mitre-privilege)', icon: '⬆️' },
  defense_evasion: { color: 'var(--mitre-defense)', icon: '🛡️' },
  credential_access: { color: 'var(--mitre-privilege)', icon: '🔑' },
  discovery: { color: 'var(--mitre-discovery)', icon: '🔍' },
  lateral_movement: { color: 'var(--mitre-lateral)', icon: '↔️' },
  collection: { color: 'var(--mitre-collection)', icon: '📁' },
  exfiltration: { color: 'var(--mitre-initial)', icon: '📤' },
  impact: { color: 'var(--threat-critical)', icon: '💥' },
};

export const THREAT_ICONS: Record<ThreatType, string> = {
  prompt_injection: '💉',
  malware_indicators: '🦠',
  phishing: '🎣',
  credential_leakage: '🔓',
  insecure_code: '⚠️',
  data_exfiltration: '📤',
  social_engineering: '🎭',
  unauthorized_access: '🚫',
  sql_injection: '🗄️',
  xss: '🌐',
  csrf: '🔄',
  cryptographic_weakness: '🔐',
};

export const CHAT_CATEGORIES: Record<ChatCategory, { icon: string; color: string }> = {
  general: { icon: '💬', color: 'var(--info)' },
  coding: { icon: '💻', color: 'var(--primary)' },
  cybersecurity: { icon: '🔒', color: 'var(--safe)' },
  threat_analysis: { icon: '🔍', color: 'var(--warning)' },
  incident_response: { icon: '🚨', color: 'var(--danger)' },
};

export const MODEL_CONFIGS: Record<ModelType, { icon: string; description: string; features: string[] }> = {
  secure: {
    icon: '🛡️',
    description: 'Maximum security with strict content filtering',
    features: ['Prompt injection protection', 'Data encryption', 'Audit logging'],
  },
  advanced: {
    icon: '⚡',
    description: 'Balanced security and performance',
    features: ['Enhanced threat detection', 'Real-time analysis', 'MITRE ATT&CK mapping'],
  },
  research: {
    icon: '🔬',
    description: 'Advanced research capabilities with comprehensive analysis',
    features: ['Full vulnerability scanning', 'Exploit analysis', 'Custom rule sets'],
  },
};
