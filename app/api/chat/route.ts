import { NextRequest, NextResponse } from "next/server";

// Type definitions for chat messages
interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

const TAMBO_API_URL = "https://api.tambo.ai/v1/chat/completions";
const TAMBO_API_KEY = process.env.NEXT_PUBLIC_TAMBO_API_KEY;

// Enhanced mock responses with more variety and context awareness
const mockResponses = [
  // Security Operations
  "I understand your question about security operations. As an EVS AI Assistant powered by Tambo AI, I can help you with threat detection, vulnerability analysis, and automated response recommendations. Your current security posture shows areas for improvement in patch management and access control.",
  "Based on your query, I recommend reviewing your current security posture. EVS provides real-time threat intelligence and automated vulnerability assessment. I've identified several critical vulnerabilities that require immediate attention.",
  "For your security concern, I suggest implementing the following measures: enable multi-factor authentication across all privileged accounts, review access logs for suspicious activity, and ensure all systems are patched to the latest versions. Would you like me to generate a detailed remediation plan?",
  "I've analyzed your request and identified several key areas to focus on: 1) Review and update your incident response procedures, 2) Schedule regular vulnerability scanning, 3) Enhance monitoring capabilities for lateral movement detection, 4) Implement least privilege access controls.",
  "The EVS AI Assistant can help you with comprehensive security analysis. I recommend running a full vulnerability assessment to identify potential entry points for attackers. Our AI-powered scanning can detect misconfigurations, outdated software, and weak credentials.",
  
  // Vulnerability Management
  "Vulnerability management is a critical component of your security program. Based on your environment, I recommend prioritizing CVE-2024-3400 and other critical vulnerabilities affecting your web servers. The remediation process should begin with isolating affected systems.",
  "Your vulnerability scan results show 7 active vulnerabilities, with 2 classified as critical. The most severe issues are related to outdated SSL/TLS configurations and missing security headers. I recommend immediate remediation of these findings.",
  "To improve your vulnerability management program, consider implementing automated patch management, continuous vulnerability scanning, and risk-based prioritization. EVS can help you track remediation progress and measure improvements over time.",
  
  // Threat Detection
  "Threat detection requires a multi-layered approach combining network monitoring, endpoint detection, and user behavior analytics. I've detected potential threat indicators in your environment that warrant further investigation.",
  "Your threat intelligence feed shows active indicators of compromise (IOCs) matching known malicious IP addresses. I recommend blocking these IPs at your firewall and reviewing logs for any connections from these sources.",
  "Advanced threat detection involves analyzing patterns in network traffic, system logs, and user behavior. EVS AI can correlate events across your environment to identify sophisticated attacks that might otherwise go undetected.",
  
  // Incident Response
  "Effective incident response requires preparation, detection, containment, eradication, and recovery. EVS provides automated containment recommendations based on the type and severity of incidents you report.",
  "For incident response, EVS offers automated containment and remediation recommendations. I've identified an active brute force attack targeting your authentication service. Immediate actions include blocking the source IP and enforcing account lockout policies.",
  "Your incident response playbook should include procedures for common attack scenarios. Based on current threats, I recommend updating your playbooks for credential stuffing attacks and ransomware incidents.",
  
  // Compliance
  "Compliance frameworks like SOC 2, ISO 27001, and GDPR require comprehensive security controls. Your current compliance score of 68% indicates significant gaps that need to be addressed.",
  "EVS supports compliance assessments for multiple frameworks. I've analyzed your environment against SOC 2 requirements and identified 4 controls that need immediate attention. These relate to access management and audit logging.",
  "To achieve compliance, you must implement technical and organizational controls aligned with framework requirements. EVS can track your compliance progress and identify gaps in your security program.",
  
  // Configuration & Setup
  "Security configuration management is essential for maintaining a strong security posture. I can help you configure your security settings based on industry best practices and compliance requirements.",
  "Proper security configuration includes: 1) Network segmentation, 2) Firewall rules, 3) System hardening, 4) Access controls, 5) Encryption. EVS provides intelligent automation for implementing these controls across your infrastructure.",
  "I recommend reviewing your current security configuration against CIS benchmarks. Your environment shows deviations from recommended settings that increase your attack surface.",
  
  // Assets
  "Asset discovery and management is the foundation of effective security operations. EVS can help you maintain an accurate inventory of your IT assets and identify unmanaged devices connecting to your network.",
  "Your asset inventory shows 156 registered devices, with 12 detected as unmanaged. These unknown devices represent potential security risks and should be investigated immediately.",
  
  // General AI Assistance
  "I'm here to help with all aspects of your security operations. Whether you need vulnerability assessments, incident analysis, compliance guidance, or security recommendations, EVS AI is ready to assist.",
  "As your security AI assistant, I can analyze threats, generate reports, and provide actionable recommendations. What specific security challenge would you like to address today?",
];

// Semantic keyword mappings for better response selection
const keywordCategories = {
  vulnerability: ['vulnerability', 'vulnerabilities', 'cve', 'scan', 'scanning', 'patch', 'patching', 'cve-', 'exploit', 'flaw', 'weakness'],
  threat: ['threat', 'threats', 'attack', 'attacks', 'malware', 'ransomware', 'phishing', 'botnet', 'ioc', 'indicator', 'malicious'],
  incident: ['incident', 'incidents', 'response', 'breach', 'compromise', 'containment', 'remediation', 'forensics', 'investigation'],
  compliance: ['compliance', 'compliant', 'audit', 'audits', 'soc2', 'iso27001', 'gdpr', 'hipaa', 'framework', 'controls', 'certification'],
  config: ['config', 'configuration', 'setup', 'hardening', 'cis', 'benchmark', 'settings', 'policy'],
  asset: ['asset', 'assets', 'device', 'devices', 'inventory', 'endpoint', 'server', 'workstation', 'network'],
  detection: ['detection', 'detect', 'monitoring', 'monitor', 'alert', 'alerts', 'siem', 'logging', 'log'],
  authentication: ['auth', 'authentication', 'mfa', 'password', 'credential', 'login', 'access', 'privilege', 'iam'],
};

// Calculate similarity score between query and category
function getCategoryScore(query: string, category: string[]): number {
  const lowerQuery = query.toLowerCase();
  let score = 0;
  for (const keyword of category) {
    if (lowerQuery.includes(keyword)) {
      score += 1;
      // Bonus for exact word match
      if (new RegExp(`\\b${keyword}\\b`).test(lowerQuery)) {
        score += 0.5;
      }
    }
  }
  return score;
}

// Get best matching category for user query
function getBestCategory(query: string): string {
  const scores: Record<string, number> = {};
  
  for (const [category, keywords] of Object.entries(keywordCategories)) {
    scores[category] = getCategoryScore(query, keywords);
  }
  
  // Find category with highest score
  const bestMatch = Object.entries(scores).reduce((best, [cat, score]) => 
    score > best[1] ? [cat, score] : best, 
    ['', 0]
  );
  
  return bestMatch[0];
}

// Get context-aware response based on conversation history
function getContextAwareResponse(messages: ChatMessage[], userMessage: string): string {
  const lowerMessage = userMessage.toLowerCase();
  const category = getBestCategory(lowerMessage);
  
  // Get recent conversation context (last 3 messages)
  const recentMessages = messages.slice(-3);
  
  // Find responses matching the category
  const categoryResponses = mockResponses.filter(r => {
    const lower = r.toLowerCase();
    if (category === 'vulnerability') return lower.includes('vulnerab');
    if (category === 'threat') return lower.includes('threat') || lower.includes('attack');
    if (category === 'incident') return lower.includes('incident') || lower.includes('response');
    if (category === 'compliance') return lower.includes('compliance') || lower.includes('audit');
    if (category === 'config') return lower.includes('config') || lower.includes('hardening');
    if (category === 'asset') return lower.includes('asset') || lower.includes('device');
    if (category === 'detection') return lower.includes('detect') || lower.includes('monitor');
    if (category === 'authentication') return lower.includes('auth') || lower.includes('access');
    return false;
  });
  
  // If we have category-specific responses, pick one
  if (categoryResponses.length > 0) {
    // Try to avoid repeating the last response
    const lastResponse = recentMessages.find(m => m.role === 'assistant')?.content;
    const unusedResponses = categoryResponses.filter(r => r !== lastResponse);
    const selectedResponses = unusedResponses.length > 0 ? unusedResponses : categoryResponses;
    return selectedResponses[Math.floor(Math.random() * selectedResponses.length)];
  }
  
  // Fallback to random response from pool, avoiding recent ones
  const recentResponses = recentMessages
    .filter(m => m.role === 'assistant')
    .map(m => m.content);
  const unusedMockResponses = mockResponses.filter(r => !recentResponses.includes(r));
  const pool = unusedMockResponses.length > 0 ? unusedMockResponses : mockResponses;
  
  return pool[Math.floor(Math.random() * pool.length)];
}

function getMockResponse(userMessage: string, messages?: ChatMessage[]): string {
  if (messages && messages.length > 0) {
    return getContextAwareResponse(messages, userMessage);
  }
  
  // Legacy single-message fallback
  const lowerMessage = userMessage.toLowerCase();
  
  if (lowerMessage.includes('vulnerability') || lowerMessage.includes('scan') || lowerMessage.includes('cve')) {
    return "I can help you with vulnerability scanning. EVS provides automated vulnerability assessment powered by Tambo AI. Would you like me to analyze your system for potential vulnerabilities?";
  }
  if (lowerMessage.includes('threat') || lowerMessage.includes('attack') || lowerMessage.includes('malware')) {
    return "EVS provides real-time threat intelligence. I've detected potential threat indicators in your environment. Would you like a detailed threat analysis report?";
  }
  if (lowerMessage.includes('incident') || lowerMessage.includes('response') || lowerMessage.includes('breach')) {
    return "For incident response, EVS offers automated containment and remediation recommendations. What's the nature of the incident you're investigating?";
  }
  if (lowerMessage.includes('compliance') || lowerMessage.includes('audit') || lowerMessage.includes('soc2')) {
    return "EVS supports compliance assessments for SOC 2, ISO 27001, and other frameworks. I can help you evaluate your compliance posture.";
  }
  if (lowerMessage.includes('config') || lowerMessage.includes('setup') || lowerMessage.includes('hardening')) {
    return "I can help you configure your security settings. EVS provides intelligent automation for security operations. What specific configuration do you need assistance with?";
  }
  if (lowerMessage.includes('asset') || lowerMessage.includes('device') || lowerMessage.includes('inventory')) {
    return "Asset management is crucial for security. EVS can help you track and secure all devices in your network. Would you like me to run an asset discovery scan?";
  }
  
  // Return random response from pool
  return mockResponses[Math.floor(Math.random() * mockResponses.length)];
}

export async function POST(request: NextRequest) {
  try {
    const { messages, model = "gpt-3.5-turbo" } = await request.json();

    if (!messages || !Array.isArray(messages)) {
      return NextResponse.json(
        { error: "Messages array is required" },
        { status: 400 }
      );
    }

    // Check if Tambo API key is available and not a demo/invalid key
    const isDemoKey = TAMBO_API_KEY?.includes('demo') || !TAMBO_API_KEY;
    
    if (isDemoKey) {
      // Use mock response for demo mode
      const lastUserMessage = messages[messages.length - 1]?.content || "";
      const mockResponse = getMockResponse(lastUserMessage, messages);
      
      // Simulate API delay
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      return NextResponse.json({ 
        response: mockResponse,
        _demo: true,
        message: "Running in demo mode with enhanced mock responses"
      });
    }

    const response = await fetch(TAMBO_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": TAMBO_API_KEY || "",
      },
      body: JSON.stringify({
        model: model,
        messages: messages,
        temperature: 0.7,
        max_tokens: 1000,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Tambo API error:", errorText);
      
      // Fallback to mock response on API error
      const lastUserMessage = messages[messages.length - 1]?.content || "";
      const mockResponse = getMockResponse(lastUserMessage, messages);
      
      return NextResponse.json({ 
        response: mockResponse,
        _fallback: true,
        message: "Tambo API unavailable, using demo mode"
      });
    }

    const data = await response.json();
    const assistantResponse = data.choices?.[0]?.message?.content || "";

    return NextResponse.json({ response: assistantResponse });
  } catch (error) {
    console.error("Tambo API error:", error);
    
    // Fallback to mock response on exception
    try {
      const { messages } = await request.json();
      const lastUserMessage = messages?.[messages.length - 1]?.content || "";
      const mockResponse = getMockResponse(lastUserMessage);
      
      return NextResponse.json({ 
        response: mockResponse,
        _errorFallback: true,
        message: "AI service temporarily unavailable, using demo mode"
      });
    } catch {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "Failed to get AI response" },
        { status: 500 }
      );
    }
  }
}
