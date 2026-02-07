// Kubernetes Client Integration Layer
// Provides a unified interface for interacting with Kubernetes clusters

import type {
  K8sPod,
  K8sDeployment,
  K8sService,
  K8sConfigMap,
  K8sSecret,
  K8sNode,
  K8sEvent,
  K8sMetrics,
  K8sPodMetrics,
  K8sNodeMetrics,
  ClusterInfo,
  K8sApiResponse,
  LogEntry,
  LogOptions,
} from "./types";

// Configuration for K8s client
export interface K8sClientConfig {
  apiServer?: string;
  token?: string;
  caCert?: string;
  namespace?: string;
  timeout?: number;
}

export class K8sClient {
  private baseUrl: string;
  private headers: HeadersInit;
  private namespace: string;
  private timeout: number;

  constructor(config: K8sClientConfig = {}) {
    this.baseUrl = config.apiServer || process.env.K8S_API_SERVER || "https://kubernetes.default.svc";
    this.namespace = config.namespace || process.env.K8S_NAMESPACE || "default";
    this.timeout = config.timeout || 30000;
    
    this.headers = {
      "Content-Type": "application/json",
      ...(config.token && { Authorization: `Bearer ${config.token}` }),
      ...(config.caCert && { "X-Certificate-Authority": config.caCert }),
    };
  }

  // Generic API request handler
  private async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        headers: { ...this.headers, ...options.headers },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.message || `HTTP ${response.status}: ${response.statusText}`);
      }

      return response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  // Set namespace for operations
  setNamespace(ns: string): void {
    this.namespace = ns;
  }

  // ==================== Pod Operations ====================

  async getPods(namespace?: string): Promise<K8sPod[]> {
    const ns = namespace || this.namespace;
    const response = await this.request<K8sApiResponse<K8sPod>>(
      `/api/v1/namespaces/${ns}/pods`
    );
    return response.items || [];
  }

  async getPod(name: string, namespace?: string): Promise<K8sPod> {
    const ns = namespace || this.namespace;
    return this.request<K8sPod>(`/api/v1/namespaces/${ns}/pods/${name}`);
  }

  async createPod(pod: Partial<K8sPod>, namespace?: string): Promise<K8sPod> {
    const ns = namespace || this.namespace;
    return this.request<K8sPod>(`/api/v1/namespaces/${ns}/pods`, {
      method: "POST",
      body: JSON.stringify(pod),
    });
  }

  async updatePod(name: string, pod: Partial<K8sPod>, namespace?: string): Promise<K8sPod> {
    const ns = namespace || this.namespace;
    return this.request<K8sPod>(`/api/v1/namespaces/${ns}/pods/${name}`, {
      method: "PUT",
      body: JSON.stringify(pod),
    });
  }

  async deletePod(name: string, namespace?: string): Promise<void> {
    const ns = namespace || this.namespace;
    await this.request(`/api/v1/namespaces/${ns}/pods/${name}`, {
      method: "DELETE",
    });
  }

  async getPodLogs(
    name: string,
    options: LogOptions = {},
    namespace?: string
  ): Promise<LogEntry[]> {
    const ns = namespace || this.namespace;
    const params = new URLSearchParams();
    
    if (options.follow) params.set("follow", "true");
    if (options.tailLines) params.set("tailLines", options.tailLines.toString());
    if (options.sinceSeconds) params.set("sinceSeconds", options.sinceSeconds.toString());
    if (options.timestamps) params.set("timestamps", "true");
    if (options.previous) params.set("previous", "true");
    if (options.container) params.set("container", options.container);

    const response = await this.request<string>(
      `/api/v1/namespaces/${ns}/pods/${name}/log?${params.toString()}`
    );

    return this.parseLogResponse(response, name, options.container);
  }

  private parseLogResponse(response: string, podName: string, container?: string): LogEntry[] {
    const lines = response.split("\n");
    return lines
      .filter((line) => line.trim())
      .map((line) => {
        const parts = line.split(" ");
        const timestamp = parts[0] || new Date().toISOString();
        const rest = parts.slice(1).join(" ");
        const stream = rest.toLowerCase().includes("stderr") ? "stderr" : "stdout";
        return {
          timestamp,
          content: rest,
          stream,
          pod: podName,
          container: container || "",
        };
      });
  }

  // ==================== Deployment Operations ====================

  async getDeployments(namespace?: string): Promise<K8sDeployment[]> {
    const ns = namespace || this.namespace;
    const response = await this.request<K8sApiResponse<K8sDeployment>>(
      `/apis/apps/v1/namespaces/${ns}/deployments`
    );
    return response.items || [];
  }

  async getDeployment(name: string, namespace?: string): Promise<K8sDeployment> {
    const ns = namespace || this.namespace;
    return this.request<K8sDeployment>(
      `/apis/apps/v1/namespaces/${ns}/deployments/${name}`
    );
  }

  async createDeployment(
    deployment: Partial<K8sDeployment>,
    namespace?: string
  ): Promise<K8sDeployment> {
    const ns = namespace || this.namespace;
    return this.request<K8sDeployment>(
      `/apis/apps/v1/namespaces/${ns}/deployments`,
      {
        method: "POST",
        body: JSON.stringify(deployment),
      }
    );
  }

  async updateDeployment(
    name: string,
    deployment: Partial<K8sDeployment>,
    namespace?: string
  ): Promise<K8sDeployment> {
    const ns = namespace || this.namespace;
    return this.request<K8sDeployment>(
      `/apis/apps/v1/namespaces/${ns}/deployments/${name}`,
      {
        method: "PUT",
        body: JSON.stringify(deployment),
      }
    );
  }

  async scaleDeployment(
    name: string,
    replicas: number,
    namespace?: string
  ): Promise<K8sDeployment> {
    const ns = namespace || this.namespace;
    const deployment = await this.getDeployment(name, ns);
    return this.updateDeployment(
      name,
      { ...deployment, spec: { ...deployment.spec, replicas } },
      ns
    );
  }

  async deleteDeployment(name: string, namespace?: string): Promise<void> {
    const ns = namespace || this.namespace;
    await this.request(`/apis/apps/v1/namespaces/${ns}/deployments/${name}`, {
      method: "DELETE",
    });
  }

  // ==================== Service Operations ====================

  async getServices(namespace?: string): Promise<K8sService[]> {
    const ns = namespace || this.namespace;
    const response = await this.request<K8sApiResponse<K8sService>>(
      `/api/v1/namespaces/${ns}/services`
    );
    return response.items || [];
  }

  async getService(name: string, namespace?: string): Promise<K8sService> {
    const ns = namespace || this.namespace;
    return this.request<K8sService>(
      `/api/v1/namespaces/${ns}/services/${name}`
    );
  }

  async createService(
    service: Partial<K8sService>,
    namespace?: string
  ): Promise<K8sService> {
    const ns = namespace || this.namespace;
    return this.request<K8sService>(`/api/v1/namespaces/${ns}/services`, {
      method: "POST",
      body: JSON.stringify(service),
    });
  }

  async deleteService(name: string, namespace?: string): Promise<void> {
    const ns = namespace || this.namespace;
    await this.request(`/api/v1/namespaces/${ns}/services/${name}`, {
      method: "DELETE",
    });
  }

  // ==================== ConfigMap Operations ====================

  async getConfigMaps(namespace?: string): Promise<K8sConfigMap[]> {
    const ns = namespace || this.namespace;
    const response = await this.request<K8sApiResponse<K8sConfigMap>>(
      `/api/v1/namespaces/${ns}/configmaps`
    );
    return response.items || [];
  }

  async getConfigMap(name: string, namespace?: string): Promise<K8sConfigMap> {
    const ns = namespace || this.namespace;
    return this.request<K8sConfigMap>(
      `/api/v1/namespaces/${ns}/configmaps/${name}`
    );
  }

  async createConfigMap(
    configMap: Partial<K8sConfigMap>,
    namespace?: string
  ): Promise<K8sConfigMap> {
    const ns = namespace || this.namespace;
    return this.request<K8sConfigMap>(
      `/api/v1/namespaces/${ns}/configmaps`,
      {
        method: "POST",
        body: JSON.stringify(configMap),
      }
    );
  }

  async deleteConfigMap(name: string, namespace?: string): Promise<void> {
    const ns = namespace || this.namespace;
    await this.request(`/api/v1/namespaces/${ns}/configmaps/${name}`, {
      method: "DELETE",
    });
  }

  // ==================== Secret Operations ====================

  async getSecrets(namespace?: string): Promise<K8sSecret[]> {
    const ns = namespace || this.namespace;
    const response = await this.request<K8sApiResponse<K8sSecret>>(
      `/api/v1/namespaces/${ns}/secrets`
    );
    return response.items || [];
  }

  async getSecret(name: string, namespace?: string): Promise<K8sSecret> {
    const ns = namespace || this.namespace;
    return this.request<K8sSecret>(
      `/api/v1/namespaces/${ns}/secrets/${name}`
    );
  }

  async createSecret(
    secret: Partial<K8sSecret>,
    namespace?: string
  ): Promise<K8sSecret> {
    const ns = namespace || this.namespace;
    return this.request<K8sSecret>(`/api/v1/namespaces/${ns}/secrets`, {
      method: "POST",
      body: JSON.stringify(secret),
    });
  }

  async deleteSecret(name: string, namespace?: string): Promise<void> {
    const ns = namespace || this.namespace;
    await this.request(`/api/v1/namespaces/${ns}/secrets/${name}`, {
      method: "DELETE",
    });
  }

  // ==================== Node Operations ====================

  async getNodes(): Promise<K8sNode[]> {
    const response = await this.request<K8sApiResponse<K8sNode>>(
      "/api/v1/nodes"
    );
    return response.items || [];
  }

  async getNode(name: string): Promise<K8sNode> {
    return this.request<K8sNode>(`/api/v1/nodes/${name}`);
  }

  // ==================== Event Operations ====================

  async getEvents(namespace?: string): Promise<K8sEvent[]> {
    const ns = namespace || this.namespace;
    const response = await this.request<K8sApiResponse<K8sEvent>>(
      `/api/v1/namespaces/${ns}/events`
    );
    return response.items || [];
  }

  async getAllEvents(): Promise<K8sEvent[]> {
    const response = await this.request<K8sApiResponse<K8sEvent>>(
      "/api/v1/events"
    );
    return response.items || [];
  }

  // ==================== Metrics Operations ====================

  async getPodMetrics(namespace?: string): Promise<K8sPodMetrics[]> {
    const ns = namespace || this.namespace;
    try {
      const response = await this.request<{ items: K8sPodMetrics[] }>(
        `/apis/metrics.k8s.io/v1beta1/namespaces/${ns}/pods`
      );
      return response.items || [];
    } catch {
      return [];
    }
  }

  async getNodeMetrics(): Promise<K8sNodeMetrics[]> {
    try {
      const response = await this.request<{ items: K8sNodeMetrics[] }>(
        "/apis/metrics.k8s.io/v1beta1/nodes"
      );
      return response.items || [];
    } catch {
      return [];
    }
  }

  async getAllMetrics(namespace?: string): Promise<K8sMetrics> {
    const [pods, nodes] = await Promise.all([
      this.getPodMetrics(namespace),
      this.getNodeMetrics(),
    ]);
    return { pods, nodes };
  }

  // ==================== Cluster Info ====================

  async getClusterInfo(): Promise<ClusterInfo> {
    const [versionInfo, nodes] = await Promise.all([
      this.request<{ gitVersion: string; major: string; minor: string; platform: string }>(
        "/version"
      ),
      this.getNodes(),
    ]);

    return {
      name: "kubernetes",
      context: "default",
      apiVersion: versionInfo.gitVersion,
      major: versionInfo.major,
      minor: versionInfo.minor,
      gitVersion: versionInfo.gitVersion,
      platform: versionInfo.platform,
      nodeCount: nodes.length,
      podCIDR: "",
      serverAddress: this.baseUrl,
    };
  }

  // ==================== Namespaces ====================

  async getNamespaces(): Promise<{ name: string; status: string }[]> {
    const response = await this.request<{
      items: Array<{ metadata: { name: string }; status: { phase: string } }>;
    }>("/api/v1/namespaces");

    return response.items.map((ns) => ({
      name: ns.metadata.name,
      status: ns.status.phase,
    }));
  }
}

// Singleton instance
let k8sClient: K8sClient | null = null;

export function getK8sClient(config?: K8sClientConfig): K8sClient {
  if (!k8sClient) {
    k8sClient = new K8sClient(config);
  }
  return k8sClient;
}

export default K8sClient;
