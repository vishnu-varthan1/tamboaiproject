"use client";

import React, { useState } from "react";
import type { DashboardPanel, K8sPod, K8sDeployment, K8sService, K8sEvent, PanelConfig } from "@/lib/k8s/types";

interface PanelRendererProps {
  panel: DashboardPanel;
  data?: {
    pods?: K8sPod[];
    deployments?: K8sDeployment[];
    services?: K8sService[];
    events?: K8sEvent[];
    metrics?: {
      cpu: { value: number; percentage: number };
      memory: { value: number; percentage: number };
      pods: { total: number; running: number; pending: number; failed: number };
    };
    logs?: string[];
  };
  onRefresh?: () => void;
  onClose?: () => void;
  onResize?: (size: "small" | "medium" | "large" | "full") => void;
  isLoading?: boolean;
  error?: string | null;
}

export default function PanelRenderer({
  panel,
  data,
  onRefresh,
  onClose,
  onResize,
  isLoading = false,
  error = null,
}: PanelRendererProps) {
  const [localData, setLocalData] = useState<unknown[]>([]);

  const getPanelHeader = () => (
    <div className="flex items-center justify-between px-4 py-2 border-b border-[#2a2a2a] bg-[#1a1a1a]">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-gray-200">{panel.title}</span>
        {isLoading && (
          <svg className="w-4 h-4 animate-spin text-[#10a37f]" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
        )}
      </div>
      <div className="flex items-center gap-1">
        {onResize && (
          <>
            <button
              onClick={() => onResize("small")}
              className="p-1 text-[#737373] hover:text-white hover:bg-[#262626] rounded transition-colors"
              title="Small"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
              </svg>
            </button>
            <button
              onClick={() => onResize("medium")}
              className="p-1 text-[#737373] hover:text-white hover:bg-[#262626] rounded transition-colors"
              title="Medium"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
              </svg>
            </button>
            <button
              onClick={() => onResize("large")}
              className="p-1 text-[#737373] hover:text-white hover:bg-[#262626] rounded transition-colors"
              title="Large"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
              </svg>
            </button>
          </>
        )}
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="p-1 text-[#737373] hover:text-white hover:bg-[#262626] rounded transition-colors"
            title="Refresh"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        )}
        {onClose && (
          <button
            onClick={onClose}
            className="p-1 text-[#737373] hover:text-red-400 hover:bg-[#262626] rounded transition-colors"
            title="Close"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );

  const getPanelSizeClass = () => {
    switch (panel.size) {
      case "small":
        return "col-span-1 row-span-1";
      case "medium":
        return "col-span-1 md:col-span-2 row-span-1";
      case "large":
        return "col-span-1 md:col-span-2 row-span-2";
      case "full":
        return "col-span-full row-span-2";
      default:
        return "col-span-1 row-span-1";
    }
  };

  const renderError = () => (
    <div className="flex items-center justify-center h-full p-4 text-center">
      <div className="text-red-400">
        <svg className="w-12 h-12 mx-auto mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <p className="text-sm">{error || "Failed to load data"}</p>
      </div>
    </div>
  );

  const renderLoading = () => (
    <div className="flex items-center justify-center h-full">
      <div className="flex items-center gap-2 text-[#10a37f]">
        <svg className="w-6 h-6 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span className="text-sm">Loading...</span>
      </div>
    </div>
  );

  const renderContent = () => {
    if (error) return renderError();
    if (isLoading) return renderLoading();

    switch (panel.type) {
      case "pods":
        return <PodPanel pods={data?.pods || []} config={panel.config} />;
      case "deployment":
        return <DeploymentPanel deployments={data?.deployments || []} config={panel.config} />;
      case "service":
        return <ServicePanel services={data?.services || []} config={panel.config} />;
      case "event":
        return <EventPanel events={data?.events || []} />;
      case "metrics":
        return <MetricsPanel metrics={data?.metrics} />;
      case "logs":
        return <LogsPanel logs={data?.logs || []} />;
      case "health":
        return <HealthPanel />;
      default:
        return (
          <div className="flex items-center justify-center h-full text-[#737373]">
            <p className="text-sm">Panel type {JSON.stringify(panel.type)} not implemented</p>
          </div>
        );
    }
  };

  return (
    <div className={`bg-[#1a1a1a] border border-[#2a2a2a] rounded-xl overflow-hidden ${getPanelSizeClass()}`}>
      {getPanelHeader()}
      <div className="p-4 h-[calc(100%-48px)] overflow-auto">
        {renderContent()}
      </div>
    </div>
  );
}

// Pod Panel Component
function PodPanel({ pods, config }: { pods: K8sPod[]; config?: PanelConfig }) {
  const getPodStatusColor = (phase: string) => {
    switch (phase.toLowerCase()) {
      case "running":
        return "text-green-400";
      case "pending":
        return "text-yellow-400";
      case "failed":
        return "text-red-400";
      case "succeeded":
        return "text-blue-400";
      default:
        return "text-gray-400";
    }
  };

  if (pods.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[#737373]">
        <p className="text-sm">No pods found</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {pods.slice(0, 10).map((pod) => (
        <div key={pod.metadata.uid} className="flex items-center justify-between p-2 bg-[#262626] rounded-lg">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`text-xs font-medium ${getPodStatusColor(pod.status?.phase || "unknown")}`}>
              {pod.status?.phase || "Unknown"}
            </span>
            <div className="min-w-0">
              <p className="text-sm text-gray-200 truncate">{pod.metadata.name}</p>
              <p className="text-xs text-[#737373]">
                {pod.spec.containers.length} container{pod.spec.containers.length !== 1 ? "s" : ""}
                {pod.spec.nodeName && ` • ${pod.spec.nodeName}`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {pod.status?.containerStatuses?.map((cs) => (
              <span
                key={cs.name}
                className={`text-xs px-1.5 py-0.5 rounded ${
                  cs.ready ? "bg-green-900 text-green-300" : "bg-red-900 text-red-300"
                }`}
              >
                {cs.name.slice(0, 3)}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// Deployment Panel Component
function DeploymentPanel({ deployments, config }: { deployments: K8sDeployment[]; config?: PanelConfig }) {
  if (deployments.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[#737373]">
        <p className="text-sm">No deployments found</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {deployments.slice(0, 10).map((deployment) => (
        <div key={deployment.metadata.uid} className="flex items-center justify-between p-2 bg-[#262626] rounded-lg">
          <div className="min-w-0">
            <p className="text-sm text-gray-200 truncate">{deployment.metadata.name}</p>
            <p className="text-xs text-[#737373]">
              {deployment.spec.replicas || 0} desired • {deployment.status?.readyReplicas || 0} ready • {deployment.status?.updatedReplicas || 0} updated
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className={`text-xs px-2 py-0.5 rounded ${
              (deployment.status?.readyReplicas || 0) >= (deployment.spec.replicas || 0)
                ? "bg-green-900 text-green-300"
                : "bg-yellow-900 text-yellow-300"
            }`}>
              {(deployment.status?.readyReplicas || 0)}/{deployment.spec.replicas || 0}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

// Service Panel Component
function ServicePanel({ services, config }: { services: K8sService[]; config?: PanelConfig }) {
  if (services.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[#737373]">
        <p className="text-sm">No services found</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {services.slice(0, 10).map((service) => (
        <div key={service.metadata.uid} className="flex items-center justify-between p-2 bg-[#262626] rounded-lg">
          <div className="min-w-0">
            <p className="text-sm text-gray-200 truncate">{service.metadata.name}</p>
            <p className="text-xs text-[#737373]">
              {service.spec.type || "ClusterIP"} • {service.spec.ports?.map((p) => `${p.port}:${p.targetPort}`).join(", ")}
            </p>
          </div>
          {service.spec.clusterIP && (
            <span className="text-xs text-[#737373]">{service.spec.clusterIP}</span>
          )}
        </div>
      ))}
    </div>
  );
}

// Event Panel Component
function EventPanel({ events }: { events: K8sEvent[] }) {
  const getEventTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case "warning":
        return "text-yellow-400";
      case "error":
        return "text-red-400";
      case "normal":
        return "text-green-400";
      default:
        return "text-blue-400";
    }
  };

  if (events.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[#737373]">
        <p className="text-sm">No events found</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {events.slice(0, 10).map((event, index) => (
        <div key={index} className="flex items-start gap-2 p-2 bg-[#262626] rounded-lg">
          <span className={`text-xs font-medium ${getEventTypeColor(event.type)}`}>
            {event.type.toUpperCase()}
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-sm text-gray-200 truncate">{event.message}</p>
            <p className="text-xs text-[#737373]">
              {event.reason} • {event.involvedObject?.kind}: {event.involvedObject?.name}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

// Metrics Panel Component
function MetricsPanel({ metrics }: { metrics?: { cpu: { value: number; percentage: number }; memory: { value: number; percentage: number }; pods: { total: number; running: number; pending: number; failed: number } } }) {
  if (!metrics) {
    return (
      <div className="flex items-center justify-center h-full text-[#737373]">
        <p className="text-sm">No metrics available</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* CPU Usage */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-[#737373]">CPU Usage</span>
          <span className="text-xs text-gray-300">{metrics.cpu.percentage.toFixed(1)}%</span>
        </div>
        <div className="h-2 bg-[#262626] rounded-full overflow-hidden">
          <div
            className="h-full bg-[#10a37f] rounded-full transition-all"
            style={{ width: `${Math.min(metrics.cpu.percentage, 100)}%` }}
          />
        </div>
      </div>

      {/* Memory Usage */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-[#737373]">Memory Usage</span>
          <span className="text-xs text-gray-300">{metrics.memory.percentage.toFixed(1)}%</span>
        </div>
        <div className="h-2 bg-[#262626] rounded-full overflow-hidden">
          <div
            className="h-full bg-[#6366f1] rounded-full transition-all"
            style={{ width: `${Math.min(metrics.memory.percentage, 100)}%` }}
          />
        </div>
      </div>

      {/* Pod Status */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-[#737373]">Pod Status</span>
          <span className="text-xs text-gray-300">
            {metrics.pods.running}/{metrics.pods.total} running
          </span>
        </div>
        <div className="flex h-2 bg-[#262626] rounded-full overflow-hidden">
          <div
            className="h-full bg-green-500"
            style={{ width: `${(metrics.pods.running / metrics.pods.total) * 100}%` }}
          />
          <div
            className="h-full bg-yellow-500"
            style={{ width: `${(metrics.pods.pending / metrics.pods.total) * 100}%` }}
          />
          <div
            className="h-full bg-red-500"
            style={{ width: `${(metrics.pods.failed / metrics.pods.total) * 100}%` }}
          />
        </div>
      </div>
    </div>
  );
}

// Logs Panel Component
function LogsPanel({ logs }: { logs: string[] }) {
  if (logs.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-[#737373]">
        <p className="text-sm">No logs available</p>
      </div>
    );
  }

  return (
    <div className="font-mono text-xs bg-[#0d0d0d] rounded-lg p-2 overflow-auto max-h-64">
      {logs.map((log, index) => (
        <div key={index} className="text-gray-300 whitespace-pre-wrap">{log}</div>
      ))}
    </div>
  );
}

// Health Panel Component
function HealthPanel() {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="w-12 h-12 rounded-full bg-green-900 flex items-center justify-center">
          <svg className="w-6 h-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <div>
          <p className="text-sm font-medium text-gray-200">Cluster Health</p>
          <p className="text-xs text-[#737373]">All systems operational</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="p-3 bg-[#262626] rounded-lg">
          <p className="text-xs text-[#737373]">Nodes</p>
          <p className="text-lg font-semibold text-green-400">Healthy</p>
        </div>
        <div className="p-3 bg-[#262626] rounded-lg">
          <p className="text-xs text-[#737373]">Control Plane</p>
          <p className="text-lg font-semibold text-green-400">Ready</p>
        </div>
        <div className="p-3 bg-[#262626] rounded-lg">
          <p className="text-xs text-[#737373]">Storage</p>
          <p className="text-lg font-semibold text-green-400">OK</p>
        </div>
        <div className="p-3 bg-[#262626] rounded-lg">
          <p className="text-xs text-[#737373]">Network</p>
          <p className="text-lg font-semibold text-green-400">Connected</p>
        </div>
      </div>
    </div>
  );
}
