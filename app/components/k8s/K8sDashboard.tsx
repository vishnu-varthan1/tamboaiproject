"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useTamboThread, useTamboThreadInput } from "@tambo-ai/react";
import type { DashboardPanel, K8sIntent, ClusterInfo } from "@/lib/k8s/types";
import { K8sCommandParser } from "@/lib/k8s/command-parser";
import PanelRenderer from "./PanelRenderer";

interface K8sDashboardProps {
  clusterInfo?: ClusterInfo;
}

interface DashboardMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: number;
  panels?: DashboardPanel[];
  intent?: K8sIntent;
}

export default function K8sDashboard({ clusterInfo }: K8sDashboardProps) {
  const { thread } = useTamboThread();
  const { value, setValue, submit } = useTamboThreadInput();
  const [messages, setMessages] = useState<DashboardMessage[]>([]);
  const [panels, setPanels] = useState<DashboardPanel[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState("default");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [clusterHealth, setClusterHealth] = useState<"healthy" | "warning" | "critical">("healthy");

  const commandParser = new K8sCommandParser();

  // Handle AI thread messages
  useEffect(() => {
    if (thread?.messages) {
      const latestMessages = thread.messages.slice(messages.length);
      for (const msg of latestMessages) {
        if (msg.role === "assistant") {
          const content = msg.content.map((p) => p.text || "").join("");
          setMessages((prev) => [
            ...prev,
            {
              id: msg.id || Date.now().toString(),
              role: "assistant",
              content,
              timestamp: Date.now(),
            },
          ]);
        }
      }
    }
  }, [thread?.messages, messages.length]);

  // Parse command and generate panels
  const handleCommand = useCallback(
    async (command: string) => {
      setIsLoading(true);
      setError(null);

      try {
        // Parse the command
        const intent = commandParser.parse(command);
        const validation = commandParser.validate(intent);

        if (!validation.valid) {
          throw new Error(validation.errors.join(", "));
        }

        // Generate panel configuration
        const panelConfig = commandParser.generatePanelConfig(intent);
        
        // Create new panel
        const newPanel: DashboardPanel = {
          id: `panel-${Date.now()}`,
          type: panelConfig.type || "pods",
          title: panelConfig.title || "Dashboard",
          size: "medium",
          position: { x: 0, y: panels.length },
          config: panelConfig.config || {},
          filters: panelConfig.filters,
          refreshInterval: panelConfig.refreshInterval,
        };

        // Add panel to dashboard
        setPanels((prev) => [...prev, newPanel]);

        // Add user message
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now().toString(),
            role: "user",
            content: command,
            timestamp: Date.now(),
            intent,
          },
        ]);

        // Add AI response
        setMessages((prev) => [
          ...prev,
          {
            id: Date.now().toString() + "-response",
            role: "assistant",
            content: generateResponse(intent),
            timestamp: Date.now(),
            panels: [newPanel],
            intent,
          },
        ]);

        // Get suggested follow-up commands
        const suggestions = commandParser.getSuggestedCommands(intent);
        setMessages((prev) => {
          const last = prev[prev.length - 1];
          return [
            ...prev.slice(0, -1),
            {
              ...last,
              content: last.content + "\n\n" + suggestions.map((s) => `• ${s}`).join("\n"),
            },
          ];
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to process command");
      } finally {
        setIsLoading(false);
      }
    },
    [panels.length, commandParser]
  );

  // Generate AI response based on intent
  const generateResponse = (intent: K8sIntent): string => {
    const responses: Record<string, string> = {
      list: `I've retrieved the ${intent.resourceType} list for ${intent.namespace || "default"} namespace.`,
      get: `Here are the details for ${intent.resourceType}: ${intent.name}`,
      describe: `Here's detailed information about ${intent.resourceType} ${intent.name}`,
      logs: `Showing logs for pod ${intent.name}`,
      health: `Cluster health status: All systems operational`,
      top: `Resource usage metrics`,
      compare: `Comparing ${intent.resourceType}s: ${intent.name} vs ${(intent.options as { compareTo?: string })?.compareTo}`,
      events: `Recent events in ${intent.namespace || "default"} namespace`,
    };

    return responses[intent.action] || `Processed command: ${intent.action} on ${intent.resourceType}`;
  };

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim() || isLoading) return;

    const command = value;
    setValue("");
    await handleCommand(command);
  };

  // Remove panel
  const removePanel = (panelId: string) => {
    setPanels((prev) => prev.filter((p) => p.id !== panelId));
  };

  // Resize panel
  const resizePanel = (panelId: string, size: "small" | "medium" | "large" | "full") => {
    setPanels((prev) =>
      prev.map((p) => (p.id === panelId ? { ...p, size } : p))
    );
  };

  // Refresh panel data
  const refreshPanel = (panelId: string) => {
    // In a real implementation, this would fetch new data from the K8s API
    console.log(`Refreshing panel: ${panelId}`);
  };

  // K8s-specific suggested commands
  const suggestedCommands = [
    { icon: "📦", title: "List all pods", desc: "Show running pods in current namespace" },
    { icon: "📊", title: "Show metrics", desc: "Display CPU and memory usage" },
    { icon: "🔍", title: "Check health", desc: "View cluster health status" },
    { icon: "📋", title: "Show events", desc: "List recent cluster events" },
    { icon: "🔄", title: "Restart deployment", desc: "Rollout restart a deployment" },
    { icon: "📈", title: "Scale deployment", desc: "Scale a deployment to desired replicas" },
  ];

  // Quick stats
  const stats = [
    { label: "Pods", value: clusterInfo?.podCIDR ? "12" : "--", status: "running" },
    { label: "Deployments", value: "5", status: "healthy" },
    { label: "Services", value: "8", status: "active" },
    { label: "Nodes", value: clusterInfo?.nodeCount ? String(clusterInfo.nodeCount) : "3", status: "ready" },
  ];

  return (
    <div className="flex h-full w-full bg-[#0d0d0d]">
      {/* Sidebar */}
      <div className="w-64 border-r border-[#2a2a2a] flex flex-col">
        {/* Cluster Info */}
        <div className="p-4 border-b border-[#2a2a2a]">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-8 h-8 rounded-lg bg-[#10a37f] flex items-center justify-center">
              <svg className="w-5 h-5 text-white" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-gray-200">Kubernetes</p>
              <p className="text-xs text-[#737373]">{clusterInfo?.name || "Connected"}</p>
            </div>
          </div>

          {/* Namespace selector */}
          <select
            value={selectedNamespace}
            onChange={(e) => setSelectedNamespace(e.target.value)}
            className="w-full bg-[#1a1a1a] border border-[#2a2a2a] rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-[#10a37f]"
          >
            <option value="default">default</option>
            <option value="kube-system">kube-system</option>
            <option value="kube-public">kube-public</option>
            <option value="monitoring">monitoring</option>
          </select>
        </div>

        {/* Quick Stats */}
        <div className="p-4 border-b border-[#2a2a2a]">
          <p className="text-xs text-[#737373] mb-3">Quick Stats</p>
          <div className="grid grid-cols-2 gap-2">
            {stats.map((stat) => (
              <div key={stat.label} className="bg-[#1a1a1a] rounded-lg p-2">
                <p className="text-lg font-semibold text-gray-200">{stat.value}</p>
                <p className="text-xs text-[#737373]">{stat.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Panel List */}
        <div className="flex-1 overflow-y-auto p-4">
          <p className="text-xs text-[#737373] mb-3">Active Panels</p>
          {panels.length === 0 ? (
            <p className="text-sm text-[#737373] text-center py-4">
              No panels yet. Ask me something!
            </p>
          ) : (
            <div className="space-y-2">
              {panels.map((panel) => (
                <div
                  key={panel.id}
                  className="flex items-center justify-between p-2 bg-[#1a1a1a] rounded-lg"
                >
                  <div className="min-w-0">
                    <p className="text-sm text-gray-200 truncate">{panel.title}</p>
                    <p className="text-xs text-[#737373]">{panel.type}</p>
                  </div>
                  <button
                    onClick={() => removePanel(panel.id)}
                    className="p-1 text-[#737373] hover:text-red-400 transition-colors"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col">
        {/* Chat/Command Area */}
        <div className="flex-1 overflow-y-auto p-4">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center min-h-full">
              {/* Header */}
              <div className="mb-8 text-center">
                <div className="w-16 h-16 rounded-2xl bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center mx-auto mb-4">
                  <svg className="w-10 h-10 text-[#10a37f]" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
                  </svg>
                </div>
                <h1 className="text-2xl font-semibold text-gray-100 mb-2">
                  Kubernetes AI Dashboard
                </h1>
                <p className="text-[#737373]">
                  Ask me anything about your cluster in natural language
                </p>
              </div>

              {/* Command Input */}
              <form onSubmit={handleSubmit} className="w-full max-w-3xl mb-8">
                <div className="relative bg-[#1a1a1a] border-2 border-[#2a2a2a] rounded-2xl focus-within:border-[#10a37f] transition-all">
                  <div className="flex items-center">
                    <svg className="w-5 h-5 text-[#737373] ml-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <textarea
                      className="w-full bg-transparent border-none outline-none resize-none max-h-48 min-h-[60px] px-3 py-4 text-base text-gray-100 placeholder-[#737373] scrollbar-hide"
                      value={value}
                      onChange={(e) => setValue(e.target.value)}
                      placeholder="Ask: Show me all pods, or: What's the CPU usage?"
                      rows={1}
                      disabled={isLoading}
                    />
                  </div>
                  <div className="flex items-center justify-between px-4 pb-4 pt-2 border-t border-[#2a2a2a] mx-4">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[#737373]">
                        {selectedNamespace} namespace
                      </span>
                    </div>
                    <button
                      type="submit"
                      disabled={!value.trim() || isLoading}
                      className="flex items-center gap-2 px-5 py-2 bg-[#10a37f] hover:bg-[#0d8a6a] disabled:opacity-50 disabled:cursor-not-allowed rounded-xl text-white font-medium transition-all"
                    >
                      <span className="text-sm">Execute</span>
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </form>

              {/* Suggested Commands */}
              <div className="w-full max-w-4xl">
                <p className="text-sm text-[#737373] text-center mb-4">Try asking</p>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {suggestedCommands.map((cmd, i) => (
                    <button
                      key={i}
                      onClick={() => setValue(cmd.title.toLowerCase().replace("show", "").trim())}
                      className="flex items-center gap-3 p-4 text-left bg-[#1a1a1a] hover:bg-[#262626] border border-[#2a2a2a] rounded-xl transition-all hover:border-[#404040] group"
                    >
                      <span className="text-xl">{cmd.icon}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-gray-200 group-hover:text-white transition-colors font-medium truncate">
                          {cmd.title}
                        </p>
                        <p className="text-xs text-[#737373] truncate">{cmd.desc}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Messages */}
              {messages.map((message) => (
                <div key={message.id}>
                  {message.role === "user" ? (
                    <div className="mb-6">
                      <div className="flex items-center gap-2 mb-3">
                        <div className="w-8 h-8 rounded-full bg-[#10a37f] flex items-center justify-center flex-shrink-0">
                          <span className="text-white text-xs font-medium">AI</span>
                        </div>
                        <span className="text-sm font-medium text-gray-300">You</span>
                      </div>
                      <p className="text-xl text-gray-100 leading-relaxed pl-11">{message.content}</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex items-center gap-2 text-xs text-[#737373] pl-11">
                        <svg className="w-4 h-4 text-[#10a37f]" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
                        </svg>
                        <span>Kubernetes AI</span>
                      </div>
                      <div className="pl-11">
                        <div className="prose prose-invert prose-sm max-w-none">
                          <p className="text-gray-100 leading-relaxed whitespace-pre-wrap text-base">
                            {message.content}
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}

              {/* Loading indicator */}
              {isLoading && (
                <div className="flex items-center gap-2 text-sm text-[#737373] pl-11">
                  <svg className="w-4 h-4 text-[#10a37f] animate-pulse" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
                  </svg>
                  <span>Processing...</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Dashboard Grid */}
        {panels.length > 0 && (
          <div className="border-t border-[#2a2a2a] p-4">
            <p className="text-sm font-medium text-gray-200 mb-4">Dashboard</p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {panels.map((panel) => (
                <PanelRenderer
                  key={panel.id}
                  panel={panel}
                  isLoading={isLoading}
                  error={error}
                  onClose={() => removePanel(panel.id)}
                  onResize={(size) => resizePanel(panel.id, size)}
                  onRefresh={() => refreshPanel(panel.id)}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
