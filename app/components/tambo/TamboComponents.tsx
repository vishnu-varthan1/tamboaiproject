import { type TamboComponent } from "@tambo-ai/react";

// ============ TAMBO GENERATIVE UI COMPONENTS ============

// Card Component
function Card({ title, children }: { 
  title?: string; 
  children: React.ReactNode;
}) {
  return (
    <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4 hover:border-[#3a3a6e] transition-all">
      {title && <h3 className="text-white font-semibold mb-2">{title}</h3>}
      {children}
    </div>
  );
}

// Button Component
function Button({ label, variant = "primary" }: {
  label: string;
  variant?: "primary" | "secondary" | "danger";
}) {
  const variants = {
    primary: "bg-[#10a37f] hover:bg-[#0d8a6a] text-white",
    secondary: "bg-[#2a2a4e] hover:bg-[#3a3a6e] text-white",
    danger: "bg-[#e74c3c] hover:bg-[#c0392b] text-white",
  };
  
  return (
    <button className={`${variants[variant]} px-4 py-2 rounded-lg font-medium transition-all`}>
      {label}
    </button>
  );
}

// StatCard Component
function StatCard({ label, value, change, icon }: {
  label: string;
  value: string | number;
  change?: string;
  icon?: string;
}) {
  return (
    <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-400 text-sm">{label}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          {change && (
            <p className={`text-sm mt-1 ${change.startsWith('+') ? 'text-green-400' : 'text-red-400'}`}>
              {change}
            </p>
          )}
        </div>
        {icon && <span className="text-3xl">{icon}</span>}
      </div>
    </div>
  );
}

// ProgressBar Component
function ProgressBar({ value, max = 100, label, color = "#10a37f" }: {
  value: number;
  max?: number;
  label?: string;
  color?: string;
}) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));
  
  return (
    <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
      {label && <p className="text-white text-sm mb-2">{label}</p>}
      <div className="h-3 bg-[#0d0d0d] rounded-full overflow-hidden">
        <div 
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${percentage}%`, backgroundColor: color }}
        />
      </div>
      <p className="text-gray-400 text-xs mt-1">{value} / {max}</p>
    </div>
  );
}

// Chart Component
function Chart({ 
  data, 
  type = "bar",
  title,
  height = 200
}: {
  data: { label: string; value: number }[];
  type?: "bar" | "line";
  title?: string;
  height?: number;
}) {
  const maxValue = Math.max(...data.map(d => d.value));
  
  return (
    <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
      {title && <h3 className="text-white font-semibold mb-4">{title}</h3>}
      <div style={{ height }}>
        {type === "bar" ? (
          <div className="flex items-end justify-between gap-2 h-full">
            {data.map((item, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1">
                <div 
                  className="w-full bg-[#10a37f] rounded-t opacity-80 hover:opacity-100 transition-opacity"
                  style={{ height: `${(item.value / maxValue) * 100}%` }}
                />
                <span className="text-xs text-gray-400 truncate w-full text-center">
                  {item.label}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="relative h-full">
            <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
              <polyline
                fill="none"
                stroke="#10a37f"
                strokeWidth="2"
                points={data.map((item, i) => {
                  const x = (i / (data.length - 1)) * 100;
                  const y = 100 - (item.value / maxValue) * 100;
                  return `${x},${y}`;
                }).join(" ")}
              />
            </svg>
          </div>
        )}
      </div>
    </div>
  );
}

// Badge Component
function Badge({ 
  label, 
  status = "default"
}: {
  label: string;
  status?: "default" | "success" | "warning" | "error" | "info";
}) {
  const colors = {
    default: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    success: "bg-green-500/20 text-green-400 border-green-500/30",
    warning: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    error: "bg-red-500/20 text-red-400 border-red-500/30",
    info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  
  return (
    <span className={`${colors[status]} px-2 py-1 rounded-full text-xs font-medium border`}>
      {label}
    </span>
  );
}

// List Component
function List({ 
  items, 
  title,
}: {
  items: { label: string; value?: string; icon?: string }[];
  title?: string;
}) {
  return (
    <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4">
      {title && <h3 className="text-white font-semibold mb-3">{title}</h3>}
      <ul className="space-y-2">
        {items.map((item, i) => (
          <li key={i} className="flex items-center gap-3 text-white">
            {item.icon && <span>{item.icon}</span>}
            <span className="flex-1">{item.label}</span>
            {item.value && <span className="text-gray-400">{item.value}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

// Alert Component
function Alert({ 
  message, 
  type = "info",
  title 
}: {
  message: string;
  type?: "info" | "success" | "warning" | "error";
  title?: string;
}) {
  const styles = {
    info: "bg-blue-500/10 border-blue-500/30 text-blue-400",
    success: "bg-green-500/10 border-green-500/30 text-green-400",
    warning: "bg-yellow-500/10 border-yellow-500/30 text-yellow-400",
    error: "bg-red-500/10 border-red-500/30 text-red-400",
  };
  
  const icons = {
    info: "ℹ️",
    success: "✅",
    warning: "⚠️",
    error: "❌",
  };
  
  return (
    <div className={`${styles[type]} border rounded-xl p-4`}>
      <div className="flex items-start gap-3">
        <span>{icons[type]}</span>
        <div>
          {title && <h4 className="font-semibold">{title}</h4>}
          <p className="text-sm">{message}</p>
        </div>
      </div>
    </div>
  );
}

// Export all components for Tambo
export const tamboComponents: TamboComponent[] = [
  {
    name: "Card",
    description: "A versatile card container for grouping content",
    component: Card,
    propsSchema: {
      type: "object",
      properties: {
        title: { type: "string" },
      },
    },
  },
  {
    name: "Button",
    description: "Interactive button with variants",
    component: Button,
    propsSchema: {
      type: "object",
      properties: {
        label: { type: "string" },
        variant: { type: "string", enum: ["primary", "secondary", "danger"] },
      },
      required: ["label"],
    },
  },
  {
    name: "StatCard",
    description: "Display statistics with labels and values",
    component: StatCard,
    propsSchema: {
      type: "object",
      properties: {
        label: { type: "string" },
        value: { type: ["string", "number"] },
        change: { type: "string" },
        icon: { type: "string" },
      },
      required: ["label", "value"],
    },
  },
  {
    name: "ProgressBar",
    description: "Visual progress indicator",
    component: ProgressBar,
    propsSchema: {
      type: "object",
      properties: {
        value: { type: "number" },
        max: { type: "number" },
        label: { type: "string" },
        color: { type: "string" },
      },
      required: ["value"],
    },
  },
  {
    name: "Chart",
    description: "Bar or line chart visualization",
    component: Chart,
    propsSchema: {
      type: "object",
      properties: {
        data: {
          type: "array",
          items: {
            type: "object",
            properties: {
              label: { type: "string" },
              value: { type: "number" },
            },
            required: ["label", "value"],
          },
        },
        type: { type: "string", enum: ["bar", "line"] },
        title: { type: "string" },
        height: { type: "number" },
      },
      required: ["data"],
    },
  },
  {
    name: "Badge",
    description: "Status badge with color variants",
    component: Badge,
    propsSchema: {
      type: "object",
      properties: {
        label: { type: "string" },
        status: { type: "string", enum: ["default", "success", "warning", "error", "info"] },
      },
      required: ["label"],
    },
  },
  {
    name: "List",
    description: "List with items",
    component: List,
    propsSchema: {
      type: "object",
      properties: {
        items: {
          type: "array",
          items: {
            type: "object",
            properties: {
              label: { type: "string" },
              value: { type: "string" },
              icon: { type: "string" },
            },
            required: ["label"],
          },
        },
        title: { type: "string" },
      },
      required: ["items"],
    },
  },
  {
    name: "Alert",
    description: "Alert messages with types",
    component: Alert,
    propsSchema: {
      type: "object",
      properties: {
        message: { type: "string" },
        type: { type: "string", enum: ["info", "success", "warning", "error"] },
        title: { type: "string" },
      },
      required: ["message"],
    },
  },
];
