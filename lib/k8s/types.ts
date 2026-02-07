// Kubernetes Types and Interfaces
// Core type definitions for the K8s dashboard

// Core K8s Resource Types
export interface K8sPod {
  apiVersion: string;
  kind: "Pod";
  metadata: K8sMetadata;
  spec: K8sPodSpec;
  status?: K8sPodStatus;
}

export interface K8sMetadata {
  name: string;
  namespace: string;
  uid: string;
  resourceVersion: string;
  creationTimestamp: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  ownerReferences?: K8sOwnerReference[];
}

export interface K8sOwnerReference {
  apiVersion: string;
  kind: string;
  name: string;
  uid: string;
  controller: boolean;
  blockOwnerDeletion: boolean;
}

export interface K8sPodSpec {
  containers: K8sContainer[];
  volumes?: K8sVolume[];
  restartPolicy?: string;
  terminationGracePeriodSeconds?: number;
  serviceAccountName?: string;
  nodeName?: string;
  hostname?: string;
  initContainers?: K8sContainer[];
}

export interface K8sContainer {
  name: string;
  image: string;
  imagePullPolicy?: string;
  command?: string[];
  args?: string[];
  ports?: K8sContainerPort[];
  env?: K8sEnvVar[];
  envFrom?: K8sEnvFrom[];
  resources?: K8sResourceRequirements;
  volumeMounts?: K8sVolumeMount[];
  livenessProbe?: K8sProbe;
  readinessProbe?: K8sProbe;
  startupProbe?: K8sProbe;
}

export interface K8sContainerPort {
  containerPort: number;
  protocol?: string;
  name?: string;
  hostPort?: number;
}

export interface K8sEnvVar {
  name: string;
  value?: string;
  valueFrom?: K8sEnvVarSource;
}

export interface K8sEnvVarSource {
  fieldRef?: K8sObjectFieldSelector;
  secretKeyRef?: K8sSecretKeySelector;
  configMapKeyRef?: K8sConfigMapKeySelector;
}

export interface K8sObjectFieldSelector {
  apiVersion: string;
  fieldPath: string;
}

export interface K8sSecretKeySelector {
  name: string;
  key: string;
  optional?: boolean;
}

export interface K8sConfigMapKeySelector {
  name: string;
  key: string;
  optional?: boolean;
}

export interface K8sEnvFrom {
  configMapRef?: K8sConfigMapEnvSource;
  secretRef?: K8sSecretEnvSource;
}

export interface K8sConfigMapEnvSource {
  name: string;
  optional?: boolean;
}

export interface K8sSecretEnvSource {
  name: string;
  optional?: boolean;
}

export interface K8sResourceRequirements {
  limits?: K8sResourceList;
  requests?: K8sResourceList;
}

export interface K8sResourceList {
  cpu?: string;
  memory?: string;
  [key: string]: string | undefined;
}

export interface K8sVolume {
  name: string;
  configMap?: { name: string; optional?: boolean };
  secret?: { secretName: string; optional?: boolean };
  emptyDir?: { medium?: string; sizeLimit?: string };
  persistentVolumeClaim?: { claimName: string };
  hostPath?: { path: string; type?: string };
}

export interface K8sVolumeMount {
  name: string;
  mountPath: string;
  subPath?: string;
  readOnly?: boolean;
}

export interface K8sProbe {
  exec?: { command: string[] };
  httpGet?: K8sHttpGetAction;
  tcpSocket?: { port: number | string };
  initialDelaySeconds?: number;
  timeoutSeconds?: number;
  periodSeconds?: number;
  successThreshold?: number;
  failureThreshold?: number;
}

export interface K8sHttpGetAction {
  path?: string;
  port: number | string;
  host?: string;
  scheme?: string;
  httpHeaders?: { name: string; value: string }[];
}

export interface K8sPodStatus {
  phase: string;
  conditions?: K8sPodCondition[];
  startTime?: string;
  initContainerStatuses?: K8sContainerStatus[];
  containerStatuses?: K8sContainerStatus[];
  message?: string;
  reason?: string;
  podIP?: string;
  hostIP?: string;
}

export interface K8sPodCondition {
  type: string;
  status: string;
  lastTransitionTime: string;
  reason?: string;
  message?: string;
}

export interface K8sContainerStatus {
  name: string;
  state: K8sContainerState;
  lastState?: K8sContainerState;
  ready: boolean;
  restartCount: number;
  image: string;
  imageID: string;
  containerID?: string;
}

export interface K8sContainerState {
  waiting?: { reason: string; message?: string };
  running?: { startedAt: string };
  terminated?: {
    exitCode: number;
    signal?: string;
    reason: string;
    message?: string;
    startedAt: string;
    finishedAt: string;
    containerID?: string;
  };
}

// Deployment Types
export interface K8sDeployment {
  apiVersion: string;
  kind: "Deployment";
  metadata: K8sMetadata;
  spec: K8sDeploymentSpec;
  status?: K8sDeploymentStatus;
}

export interface K8sDeploymentSpec {
  replicas?: number;
  selector: K8sLabelSelector;
  template: K8sPodTemplateSpec;
  strategy?: K8sDeploymentStrategy;
  minReadySeconds?: number;
  revisionHistoryLimit?: number;
  paused?: boolean;
  progressDeadlineSeconds?: number;
}

export interface K8sDeploymentStrategy {
  type: string;
  rollingUpdate?: K8sRollingUpdateDeployment;
  recreate?: Record<string, never>;
}

export interface K8sRollingUpdateDeployment {
  maxUnavailable?: number | string;
  maxSurge?: number | string;
}

export interface K8sDeploymentStatus {
  observedGeneration: number;
  replicas: number;
  updatedReplicas: number;
  readyReplicas: number;
  availableReplicas: number;
  unavailableReplicas?: number;
  conditions?: K8sDeploymentCondition[];
}

export interface K8sDeploymentCondition {
  type: string;
  status: string;
  lastUpdateTime?: string;
  lastTransitionTime?: string;
  reason?: string;
  message?: string;
}

export interface K8sLabelSelector {
  matchLabels?: Record<string, string>;
  matchExpressions?: K8sLabelSelectorRequirement[];
}

export interface K8sLabelSelectorRequirement {
  key: string;
  operator: string;
  values?: string[];
}

export interface K8sPodTemplateSpec {
  metadata?: K8sMetadata;
  spec?: K8sPodSpec;
}

// Service Types
export interface K8sService {
  apiVersion: string;
  kind: "Service";
  metadata: K8sMetadata;
  spec: K8sServiceSpec;
  status?: Record<string, unknown>;
}

export interface K8sServiceSpec {
  type?: string;
  selector?: Record<string, string>;
  ports?: K8sServicePort[];
  clusterIP?: string;
  externalIPs?: string[];
  loadBalancerIP?: string;
  externalName?: string;
  sessionAffinity?: string;
  healthCheckNodePort?: number;
}

export interface K8sServicePort {
  name?: string;
  protocol?: string;
  port: number;
  targetPort?: number | string;
  nodePort?: number;
}

// ConfigMap and Secret Types
export interface K8sConfigMap {
  apiVersion: string;
  kind: "ConfigMap";
  metadata: K8sMetadata;
  data?: Record<string, string>;
  binaryData?: Record<string, string>;
}

export interface K8sSecret {
  apiVersion: string;
  kind: "Secret";
  metadata: K8sMetadata;
  type?: string;
  data?: Record<string, string>;
  stringData?: Record<string, string>;
}

// Node Types
export interface K8sNode {
  apiVersion: string;
  kind: "Node";
  metadata: K8sMetadata;
  spec?: K8sNodeSpec;
  status?: K8sNodeStatus;
}

export interface K8sNodeSpec {
  podCIDR?: string;
  podCIDRs?: string[];
  externalID?: string;
  providerID?: string;
  taints?: K8sTaint[];
  unschedulable?: boolean;
}

export interface K8sTaint {
  key: string;
  value?: string;
  effect: string;
  timeAdded?: string;
}

export interface K8sNodeStatus {
  capacity?: K8sResourceList;
  allocatable?: K8sResourceList;
  conditions?: K8sNodeCondition[];
  addresses?: K8sNodeAddress[];
  images?: K8sNodeImage[];
  volumesInUse?: string[];
  volumesAttached?: K8sNodeVolumesAttached[];
}

export interface K8sNodeCondition {
  type: string;
  status: string;
  lastHeartbeatTime?: string;
  lastTransitionTime?: string;
  reason?: string;
  message?: string;
}

export interface K8sNodeAddress {
  type: string;
  address: string;
}

export interface K8sNodeImage {
  names: string[];
  sizeBytes: number;
}

export interface K8sNodeVolumesAttached {
  name: string;
  devicePath: string;
}

// Event Types
export interface K8sEvent {
  apiVersion: string;
  kind: "Event";
  metadata: K8sMetadata;
  involvedObject: K8sObjectReference;
  reason: string;
  message: string;
  type: string;
  count?: number;
  firstTimestamp?: string;
  lastTimestamp?: string;
  source?: K8sEventSource;
  reportingComponent?: string;
  reportingInstance?: string;
}

export interface K8sObjectReference {
  apiVersion?: string;
  kind?: string;
  name: string;
  namespace?: string;
  uid?: string;
  resourceVersion?: string;
  fieldPath?: string;
}

export interface K8sEventSource {
  component?: string;
  host?: string;
}

// Metrics Types
export interface K8sMetrics {
  pods?: K8sPodMetrics[];
  nodes?: K8sNodeMetrics[];
  containers?: K8sContainerMetrics[];
}

export interface K8sPodMetrics {
  metadata: K8sMetadata;
  timestamp: string;
  window: string;
  usage: {
    cpu: string;
    memory: string;
  };
}

export interface K8sNodeMetrics {
  metadata: K8sMetadata;
  timestamp: string;
  window: string;
  usage: {
    cpu: string;
    memory: string;
  };
}

export interface K8sContainerMetrics {
  metadata: K8sObjectReference;
  timestamp: string;
  window: string;
  usage: {
    cpu: string;
    memory: string;
  };
}

// Dashboard Panel Types
export type PanelType = 
  | "pods"
  | "deployment"
  | "service"
  | "configmap"
  | "secret"
  | "node"
  | "event"
  | "metrics"
  | "logs"
  | "health"
  | "comparison"
  | "topology"
  | "timeline";

export interface DashboardPanel {
  id: string;
  type: PanelType;
  title: string;
  size: "small" | "medium" | "large" | "full";
  position: { x: number; y: number };
  config: PanelConfig;
  filters?: PanelFilters;
  refreshInterval?: number;
}

export interface PanelConfig {
  namespace?: string;
  resourceKind?: string;
  labelSelector?: Record<string, string>;
  fieldSelector?: string;
  showLabels?: boolean;
  showAnnotations?: boolean;
  showEvents?: boolean;
  timeRange?: string;
  metrics?: string[];
  chartType?: "line" | "bar" | "area" | "pie";
}

export interface PanelFilters {
  status?: string[];
  phase?: string[];
  labels?: Record<string, string>;
  search?: string;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
}

// AI Intent Types
export interface K8sIntent {
  action: K8sAction;
  resourceType: string;
  namespace?: string;
  name?: string;
  labels?: Record<string, string>;
  options?: Record<string, unknown>;
}

export type K8sAction =
  | "list"
  | "get"
  | "describe"
  | "create"
  | "update"
  | "delete"
  | "scale"
  | "restart"
  | "logs"
  | "exec"
  | "port-forward"
  | "apply"
  | "describe"
  | "top"
  | "events"
  | "compare"
  | "health"
  | "debug"
  | "analyze";

// Cluster Info Types
export interface ClusterInfo {
  name: string;
  context: string;
  apiVersion: string;
  major: string;
  minor: string;
  gitVersion: string;
  platform: string;
  nodeCount: number;
  podCIDR: string;
  serverAddress: string;
}

// API Response Types
export interface K8sApiResponse<T> {
  kind: string;
  apiVersion: string;
  metadata: {
    resourceVersion: string;
    continue?: string;
  };
  items?: T[];
  item?: T;
  status?: string;
  code?: number;
  message?: string;
}

// Dashboard State Types
export interface DashboardState {
  panels: DashboardPanel[];
  selectedNamespace: string;
  selectedResource: string | null;
  isLoading: boolean;
  error: string | null;
  lastUpdated: number | null;
}

// Log Types
export interface LogEntry {
  timestamp: string;
  content: string;
  stream: "stdout" | "stderr";
  pod: string;
  container: string;
}

export interface LogOptions {
  follow?: boolean;
  tailLines?: number;
  sinceSeconds?: number;
  timestamps?: boolean;
  previous?: boolean;
  container?: string;
}

// Exec Types
export interface ExecOptions {
  container?: string;
  command?: string[];
  interactive?: boolean;
  tty?: boolean;
}

// Comparison Types
export interface ResourceComparison {
  resource1: K8sPod | K8sDeployment | K8sService;
  resource2: K8sPod | K8sDeployment | K8sService;
  differences: ComparisonDifference[];
}

export interface ComparisonDifference {
  path: string;
  value1: unknown;
  value2: unknown;
  type: "added" | "removed" | "modified";
}

// Topology Types
export interface TopologyNode {
  id: string;
  type: "pod" | "deployment" | "service" | "configmap" | "secret" | "node";
  name: string;
  namespace: string;
  status: string;
  labels?: Record<string, string>;
  x?: number;
  y?: number;
}

export interface TopologyEdge {
  source: string;
  target: string;
  type: "connects" | "depends" | "controls";
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}
