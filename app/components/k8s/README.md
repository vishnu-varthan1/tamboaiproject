# Kubernetes AI Dashboard

An advanced, AI-powered Kubernetes dashboard that converts natural language commands into real-time cluster insights and dynamic UI panels.

## Features

### Natural Language Commands
- **List Resources**: "Show me all pods", "List all deployments"
- **View Logs**: "Show me the logs for pod xyz", "Tail the logs"
- **Check Health**: "Show me the cluster health", "What's the status?"
- **Get Metrics**: "Show me CPU usage", "Display memory metrics"
- **Compare Resources**: "Compare pod xyz with pod abc"
- **Debug**: "Debug pod xyz", "Analyze deployment xyz"

### Dynamic Dashboard Panels
The interface builds itself based on user intent. Panels include:
- **Pods Panel**: Real-time pod status, containers, restarts
- **Deployments Panel**: Replica counts, ready status, scaling
- **Services Panel**: Service types, ports, cluster IPs
- **Metrics Panel**: CPU/Memory usage with visual charts
- **Logs Panel**: Streaming logs with timestamp support
- **Health Panel**: Cluster health overview with component status
- **Events Panel**: Recent cluster events with filtering

### AI-Powered Features
- **Command Parser**: Converts natural language to K8s API calls
- **Intent Recognition**: Identifies action, resource type, and filters
- **Suggested Commands**: Proactive follow-up suggestions based on context
- **Error Handling**: Smart error messages with recovery suggestions

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    K8sDashboard                          │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Sidebar    │  │  Command     │  │  Panel Grid  │  │
│  │  - Stats    │  │  Input       │  │  - Dynamic   │  │
│  │  - Panels   │  │  - Suggestions│  │  - Resizable │  │
│  └─────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                 K8sCommandParser                         │
│  - Natural language parsing                              │
│  - Intent recognition                                    │
│  - Panel generation                                      │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│                   K8sClient                              │
│  - Pod operations                                        │
│  - Deployment operations                                 │
│  - Service operations                                    │
│  - Metrics collection                                    │
│  - Event streaming                                       │
└─────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables
```env
K8S_API_SERVER=https://kubernetes.default.svc
K8S_TOKEN=your-service-account-token
K8S_NAMESPACE=default
```

### In-Cluster Usage
The dashboard automatically uses in-cluster credentials when running inside a Kubernetes cluster.

### Local Development
Point `K8S_API_SERVER` to your local cluster or remote cluster API server.

## Usage

1. **Switch to K8s Dashboard**: Click the "K8s" tab in the sidebar
2. **Enter Natural Language Command**: 
   - "Show me all pods in default namespace"
   - "Display CPU and memory usage"
   - "List all events"
3. **View Dynamic Panels**: Panels appear based on your query
4. **Interact with Panels**: Resize, refresh, or close panels as needed

## Supported Commands

| Command Pattern | Action | Example |
|----------------|--------|---------|
| `list/show/get [resources]` | List resources | "list pods" |
| `describe [resource] [name]` | Get details | "describe pod myapp" |
| `logs/tail [pod] [options]` | View logs | "logs myapp" |
| `health/status` | Cluster health | "show health" |
| `metrics/top` | Resource metrics | "show metrics" |
| `compare [resource] [name1] with [name2]` | Compare | "compare pod a with b" |
| `events` | List events | "show events" |
| `scale [deployment] [replicas]` | Scale deployment | "scale myapp to 5" |

## Panel Types

- **small**: Single resource view
- **medium**: List view with details
- **large**: Full list with filtering
- **full**: Complete dashboard view

## Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

## Security

- Uses Kubernetes service account tokens
- Supports RBAC-aware operations
- Read-only by default (can be configured for mutations)
