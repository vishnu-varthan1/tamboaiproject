// AI Command Parser for Kubernetes Intents
// Converts natural language commands into structured K8s operations

import type { K8sIntent, K8sAction, PanelType, DashboardPanel } from "./types";

// Intent patterns for natural language processing
interface IntentPattern {
  regex: RegExp;
  action: K8sAction;
  resourceType: string;
  priority: number;
}

// Common patterns for K8s commands
const INTENT_PATTERNS: IntentPattern[] = [
  // Pod patterns
  { regex: /show(?: me)?(?: all)? pods?/i, action: "list", resourceType: "pod", priority: 10 },
  { regex: /list(?: all)? pods?/i, action: "list", resourceType: "pod", priority: 10 },
  { regex: /get(?: all)? pods?/i, action: "get", resourceType: "pod", priority: 10 },
  { regex: /describe\s+(?:pod\s+)?([a-zA-Z0-9-]+)/i, action: "describe", resourceType: "pod", priority: 10 },
  { regex: /show\s+(?:me\s+)?(?:the\s+)?logs?\s+(?:of\s+)?(?:pod\s+)?([a-zA-Z0-9-]+)/i, action: "logs", resourceType: "pod", priority: 10 },
  { regex: /tail\s+(?:the\s+)?logs?\s+(?:of\s+)?(?:pod\s+)?([a-zA-Z0-9-]+)/i, action: "logs", resourceType: "pod", priority: 10 },
  { regex: /follow\s+(?:the\s+)?logs?\s+(?:of\s+)?(?:pod\s+)?([a-zA-Z0-9-]+)/i, action: "logs", resourceType: "pod", priority: 10 },
  { regex: /delete\s+(?:pod\s+)?([a-zA-Z0-9-]+)/i, action: "delete", resourceType: "pod", priority: 10 },
  { regex: /restart\s+(?:pod\s+)?([a-zA-Z0-9-]+)/i, action: "restart", resourceType: "pod", priority: 10 },
  { regex: /scale\s+(?:pod\s+)?([a-zA-Z0-9-]+)\s+(?:to\s+)?(\d+)/i, action: "scale", resourceType: "pod", priority: 10 },
  
  // Deployment patterns
  { regex: /show(?: me)?(?: all)? deployments?/i, action: "list", resourceType: "deployment", priority: 10 },
  { regex: /list(?: all)? deployments?/i, action: "list", resourceType: "deployment", priority: 10 },
  { regex: /get(?: all)? deployments?/i, action: "get", resourceType: "deployment", priority: 10 },
  { regex: /describe\s+(?:deployment\s+)?([a-zA-Z0-9-]+)/i, action: "describe", resourceType: "deployment", priority: 10 },
  { regex: /scale\s+(?:deployment\s+)?([a-zA-Z0-9-]+)\s+(?:to\s+)?(\d+)/i, action: "scale", resourceType: "deployment", priority: 10 },
  { regex: /rollout\s+restart\s+(?:deployment\s+)?([a-zA-Z0-9-]+)/i, action: "restart", resourceType: "deployment", priority: 10 },
  
  // Service patterns
  { regex: /show(?: me)?(?: all)? services?/i, action: "list", resourceType: "service", priority: 10 },
  { regex: /list(?: all)? services?/i, action: "list", resourceType: "service", priority: 10 },
  { regex: /get(?: all)? services?/i, action: "get", resourceType: "service", priority: 10 },
  { regex: /describe\s+(?:service\s+)?([a-zA-Z0-9-]+)/i, action: "describe", resourceType: "service", priority: 10 },
  
  // ConfigMap patterns
  { regex: /show(?: me)?(?: all)? configmaps?/i, action: "list", resourceType: "configmap", priority: 10 },
  { regex: /list(?: all)? configmaps?/i, action: "list", resourceType: "configmap", priority: 10 },
  { regex: /describe\s+(?:configmap\s+)?([a-zA-Z0-9-]+)/i, action: "describe", resourceType: "configmap", priority: 10 },
  
  // Secret patterns
  { regex: /show(?: me)?(?: all)? secrets?/i, action: "list", resourceType: "secret", priority: 10 },
  { regex: /list(?: all)? secrets?/i, action: "list", resourceType: "secret", priority: 10 },
  
  // Node patterns
  { regex: /show(?: me)?(?: all)? nodes?/i, action: "list", resourceType: "node", priority: 10 },
  { regex: /list(?: all)? nodes?/i, action: "list", resourceType: "node", priority: 10 },
  { regex: /describe\s+(?:node\s+)?([a-zA-Z0-9-]+)/i, action: "describe", resourceType: "node", priority: 10 },
  
  // Event patterns
  { regex: /show(?: me)?(?: all)? events?/i, action: "events", resourceType: "event", priority: 10 },
  { regex: /list(?: all)? events?/i, action: "list", resourceType: "event", priority: 10 },
  { regex: /show(?: me)?(?: the)?(?: recent)?(?: last)? events?/i, action: "events", resourceType: "event", priority: 10 },
  
  // Metrics patterns
  { regex: /show(?: me)?(?: the)?(?: CPU|memory|cpu|memory)\s*(?:usage|metrics)?/i, action: "top", resourceType: "metrics", priority: 10 },
  { regex: /show(?: me)?(?: the)? metrics?/i, action: "top", resourceType: "metrics", priority: 10 },
  { regex: /resource(?:s)?\s+(?:usage|metrics)/i, action: "top", resourceType: "metrics", priority: 10 },
  
  // Health patterns
  { regex: /show(?: me)?(?: the)?(?: cluster)? health/i, action: "health", resourceType: "cluster", priority: 10 },
  { regex: /cluster(?: status)?/i, action: "health", resourceType: "cluster", priority: 10 },
  { regex: /health(?: of)?(?: the)?(?: cluster)?/i, action: "health", resourceType: "cluster", priority: 10 },
  
  // Comparison patterns
  { regex: /compare\s+(?:pod|deployment|service)\s+([a-zA-Z0-9-]+)\s+(?:with|to)\s+([a-zA-Z0-9-]+)/i, action: "compare", resourceType: "pod", priority: 10 },
  { regex: /diff\s+(?:pod|deployment|service)\s+([a-zA-Z0-9-]+)\s+(?:with|to)\s+([a-zA-Z0-9-]+)/i, action: "compare", resourceType: "pod", priority: 10 },
  
  // Analysis patterns
  { regex: /analyze\s+(?:pod|deployment|service)\s+([a-zA-Z0-9-]+)/i, action: "analyze", resourceType: "pod", priority: 10 },
  { regex: /debug\s+(?:pod\s+)?([a-zA-Z0-9-]+)/i, action: "debug", resourceType: "pod", priority: 10 },
  
  // Namespace patterns
  { regex: /switch(?: to)?\s+namespace\s+([a-zA-Z0-9-]+)/i, action: "list", resourceType: "namespace", priority: 10 },
  { regex: /use\s+namespace\s+([a-zA-Z0-9-]+)/i, action: "list", resourceType: "namespace", priority: 10 },
  
  // General patterns
  { regex: /apply\s+(?:the|this)?\s*(?:yaml|manifest)?/i, action: "apply", resourceType: "deployment", priority: 5 },
  { regex: /create\s+(?:a\s+)?(?:pod|deployment|service|configmap|secret)/i, action: "create", resourceType: "deployment", priority: 5 },
];

// Panel type mappings
const ACTION_PANEL_MAP: Record<string, PanelType> = {
  list: "pods",
  get: "pods",
  describe: "pods",
  logs: "logs",
  delete: "pods",
  restart: "pods",
  scale: "deployment",
  create: "deployment",
  update: "deployment",
  apply: "deployment",
  events: "event",
  top: "metrics",
  health: "health",
  compare: "comparison",
  analyze: "pods",
  debug: "pods",
};

export class K8sCommandParser {
  private patterns: IntentPattern[];

  constructor() {
    // Sort patterns by priority (higher priority first)
    this.patterns = INTENT_PATTERNS.sort((a, b) => b.priority - a.priority);
  }

  // Parse natural language command into structured intent
  parse(command: string): K8sIntent {
    const trimmedCommand = command.trim();
    
    for (const pattern of this.patterns) {
      const match = trimmedCommand.match(pattern.regex);
      if (match) {
        const intent = this.buildIntent(pattern, match, trimmedCommand);
        return intent;
      }
    }

    // Default to list action with generic response
    return {
      action: "list",
      resourceType: "pod",
      options: { unrecognized: true, originalCommand: trimmedCommand },
    };
  }

  private buildIntent(
    pattern: IntentPattern,
    match: RegExpMatchArray,
    command: string
  ): K8sIntent {
    const intent: K8sIntent = {
      action: pattern.action,
      resourceType: pattern.resourceType,
    };

    // Extract name from capture groups
    if (match.length > 1) {
      // Handle multiple capture groups (for comparison commands)
      if (match.length === 3 && pattern.action === "compare") {
        intent.name = match[1];
        intent.options = { compareTo: match[2] };
      } else if (pattern.action === "scale") {
        intent.name = match[1];
        intent.options = { replicas: parseInt(match[2], 10) };
      } else if (pattern.action === "list" && pattern.resourceType === "namespace") {
        intent.namespace = match[1];
      } else {
        intent.name = match[1];
      }
    }

    // Extract namespace from command
    const namespaceMatch = command.match(/in\s+namespace\s+([a-zA-Z0-9-]+)/i);
    if (namespaceMatch) {
      intent.namespace = namespaceMatch[1];
    }

    // Extract labels from command
    const labelsMatch = command.match(/with\s+labels?\s+([^,]+)/i);
    if (labelsMatch) {
      intent.labels = this.parseLabels(labelsMatch[1]);
    }

    // Extract time range
    const timeMatch = command.match(/(?:last|past|since)\s+(\d+)\s+(minute|hour|day|week)s?/i);
    if (timeMatch) {
      const value = parseInt(timeMatch[1], 10);
      const unit = timeMatch[2].toLowerCase();
      const multiplier = unit === "minute" ? 60 : unit === "hour" ? 3600 : unit === "day" ? 86400 : 604800;
      intent.options = {
        ...intent.options,
        sinceSeconds: value * multiplier,
      };
    }

    // Add raw command for reference
    intent.options = {
      ...intent.options,
      rawCommand: command,
    };

    return intent;
  }

  private parseLabels(labelString: string): Record<string, string> {
    const labels: Record<string, string> = {};
    const pairs = labelString.split(/,\s*/);
    
    for (const pair of pairs) {
      const [key, value] = pair.split(/\s*=\s*/);
      if (key && value) {
        labels[key.trim()] = value.trim();
      }
    }
    
    return labels;
  }

  // Generate panel configuration from intent
  generatePanelConfig(intent: K8sIntent): Partial<DashboardPanel> {
    const panelType = ACTION_PANEL_MAP[intent.action] || "pods";
    
    return {
      type: panelType,
      title: this.generatePanelTitle(intent),
      config: {
        namespace: intent.namespace,
        resourceKind: intent.resourceType,
        labelSelector: intent.labels,
        showLabels: true,
        showEvents: true,
      },
      filters: {
        search: intent.name,
        status: [],
      },
      refreshInterval: 30000, // 30 seconds default
    };
  }

  private generatePanelTitle(intent: K8sIntent): string {
    const actionTitles: Record<string, string> = {
      list: "List",
      get: "Get",
      describe: "Details",
      logs: "Logs",
      delete: "Delete",
      restart: "Restart",
      scale: "Scale",
      create: "Create",
      update: "Update",
      apply: "Apply",
      events: "Events",
      top: "Metrics",
      health: "Health",
      compare: "Compare",
      analyze: "Analyze",
      debug: "Debug",
    };

    const resourceTitles: Record<string, string> = {
      pod: "Pods",
      deployment: "Deployments",
      service: "Services",
      configmap: "ConfigMaps",
      secret: "Secrets",
      node: "Nodes",
      event: "Events",
      metrics: "Metrics",
      cluster: "Cluster",
      namespace: "Namespaces",
    };

    const actionTitle = actionTitles[intent.action] || intent.action;
    const resourceTitle = resourceTitles[intent.resourceType] || intent.resourceType;
    
    if (intent.name) {
      return `${actionTitle} ${resourceTitle}: ${intent.name}`;
    }
    
    return `${actionTitle} ${resourceTitle}`;
  }

  // Get suggested follow-up commands
  getSuggestedCommands(intent: K8sIntent): string[] {
    const suggestions: string[] = [];

    switch (intent.action) {
      case "list":
        if (intent.resourceType === "pod") {
          suggestions.push(
            `Show me the logs for a specific pod`,
            `Show me the health of the cluster`,
            `List all deployments`,
            `Show me CPU and memory usage`
          );
        }
        break;
      case "logs":
        suggestions.push(
          `Show me the previous logs`,
          `Follow the logs in real-time`,
          `Show me the pod events`,
          `Describe this pod`
        );
        break;
      case "health":
        suggestions.push(
          `Show me all pods`,
          `List all events`,
          `Show me node status`,
          `Show me resource usage`
        );
        break;
      case "top":
        suggestions.push(
          `Show me the top consumers`,
          `List pods by CPU usage`,
          `Show me memory usage over time`,
          `Compare resource usage between pods`
        );
        break;
      default:
        suggestions.push(
          `Show me more details`,
          `List all ${intent.resourceType}s`,
          `Show me the events`,
          `What is the health status?`
        );
    }

    return suggestions;
  }

  // Validate intent
  validate(intent: K8sIntent): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate action
    const validActions: K8sAction[] = [
      "list", "get", "describe", "create", "update", "delete",
      "scale", "restart", "logs", "exec", "port-forward", "apply",
      "describe", "top", "events", "compare", "health", "debug", "analyze",
    ];
    
    if (!validActions.includes(intent.action)) {
      errors.push(`Invalid action: ${intent.action}`);
    }

    // Validate resource type
    const validResources = ["pod", "deployment", "service", "configmap", "secret", "node", "event", "metrics", "cluster", "namespace"];
    if (!validResources.includes(intent.resourceType)) {
      errors.push(`Invalid resource type: ${intent.resourceType}`);
    }

    // Validate namespace format
    if (intent.namespace && !/^[a-zA-Z0-9-]+$/.test(intent.namespace)) {
      errors.push(`Invalid namespace format: ${intent.namespace}`);
    }

    // Validate name format
    if (intent.name && !/^[a-zA-Z0-9-]+$/.test(intent.name)) {
      errors.push(`Invalid resource name format: ${intent.name}`);
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

export default K8sCommandParser;
