"use client";

import { useState } from "react";
import { TamboProvider, useTamboThread, useTamboThreadInput } from "@tambo-ai/react";
import { tamboComponents } from "@/app/components/tambo/TamboComponents";

// ============ ADVANCED TAMBO DEMO COMPONENTS ============

function DemoCard({ title, children, action }: { 
  title: string; 
  children: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-xl p-4 hover:border-[#3a3a6e] transition-all">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-white font-semibold">{title}</h3>
        {action}
      </div>
      {children}
    </div>
  );
}

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

function MiniChart({ data, label }: { data: number[]; label: string }) {
  const max = Math.max(...data);
  return (
    <div className="space-y-1">
      <div className="flex items-end justify-between gap-1 h-16">
        {data.map((value, i) => (
          <div
            key={i}
            className="flex-1 bg-[#10a37f] rounded-t opacity-70 hover:opacity-100 transition-opacity"
            style={{ height: `${(value / max) * 100}%` }}
          />
        ))}
      </div>
      <p className="text-xs text-gray-400 text-center">{label}</p>
    </div>
  );
}

function SystemStatus({ name, status, details }: {
  name: string;
  status: "healthy" | "warning" | "error";
  details: string;
}) {
  const colors = {
    healthy: "bg-green-500",
    warning: "bg-yellow-500",
    error: "bg-red-500",
  };
  
  return (
    <div className="flex items-center gap-3 p-3 bg-[#0d0d0d] rounded-lg">
      <div className={`w-2 h-2 rounded-full ${colors[status]}`} />
      <div className="flex-1">
        <p className="text-white text-sm font-medium">{name}</p>
        <p className="text-gray-500 text-xs">{details}</p>
      </div>
    </div>
  );
}

// ============ CHAT COMPONENT ============

function ChatInterface() {
  const { thread } = useTamboThread();
  const { value, setValue, submit, isPending } = useTamboThreadInput();

  return (
    <div className="h-full flex flex-col">
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {thread?.messages.length === 0 ? (
          <div className="text-center py-8">
            <div className="w-16 h-16 rounded-2xl bg-[#10a37f]/10 border border-[#10a37f]/20 flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <h3 className="text-white font-semibold mb-2">AI Assistant</h3>
            <p className="text-gray-400 text-sm max-w-sm mx-auto">
              Ask me anything - I can generate charts, tables, stats, and more using Tambo AI&apos;s generative UI.
            </p>
          </div>
        ) : (
          thread?.messages.map((message, i) => (
            <div
              key={i}
              className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[80%] rounded-2xl px-4 py-2 ${
                  message.role === 'user'
                    ? 'bg-[#10a37f] text-white'
                    : 'bg-[#1a1a2e] border border-[#2a2a4e] text-white'
                }`}
              >
                {typeof message.content === 'string' ? (
                  <p className="text-sm">{message.content}</p>
                ) : (
                  <div className="space-y-2">
                    {message.content?.map((content, j) => (
                      <p key={j} className="text-sm">{content?.text}</p>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))
        )}
        {isPending && (
          <div className="flex justify-start">
            <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-2xl px-4 py-2">
              <div className="flex gap-1">
                <span className="w-2 h-2 bg-[#10a37f] rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="w-2 h-2 bg-[#10a37f] rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="w-2 h-2 bg-[#10a37f] rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Input Area */}
      <div className="p-4 border-t border-[#2a2a4e]">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submit();
          }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Ask me to generate a chart, table, stats..."
            className="flex-1 bg-[#0d0d0d] border border-[#2a2a4e] rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#10a37f]"
          />
          <button
            type="submit"
            disabled={isPending || !value.trim()}
            className="px-6 py-3 bg-[#10a37f] text-white rounded-xl font-medium hover:bg-[#0d8a6a] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Send
          </button>
        </form>
      </div>
    </div>
  );
}

// ============ MAIN PAGE ============

const TABS = ["overview", "chat", "analytics"] as const;
type Tab = typeof TABS[number];

function Dashboard() {
  const [activeTab, setActiveTab] = useState<Tab>("overview");

  return (
    <div className="min-h-screen bg-[#0d0d0d] flex">
      {/* Sidebar */}
      <aside className="w-64 border-r border-[#2a2a4e] p-4">
        <div className="mb-8">
          <h1 className="text-xl font-bold text-white">AI Chat</h1>
          <p className="text-xs text-gray-500 mt-1">Powered by Tambo AI</p>
        </div>
        
        <nav className="space-y-1">
          {[
            { id: "overview" as Tab, label: "Overview", icon: "📊" },
            { id: "chat" as Tab, label: "AI Chat", icon: "💬" },
            { id: "analytics" as Tab, label: "Analytics", icon: "📈" },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm transition-colors ${
                activeTab === item.id
                  ? "bg-[#10a37f]/10 text-[#10a37f] border border-[#10a37f]/20"
                  : "text-gray-400 hover:text-white hover:bg-[#1a1a2e]"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        <div className="mt-8 p-4 bg-[#1a1a2e] rounded-xl border border-[#2a2a4e]">
          <p className="text-xs text-gray-400 mb-2">Quick Stats</p>
          <div className="space-y-2">
            <MiniChart data={[65, 80, 45, 90, 70, 55]} label="7d" />
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto">
        {activeTab === "overview" && (
          <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-white">Dashboard</h2>
                <p className="text-gray-400">Welcome to your AI-powered dashboard</p>
              </div>
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-green-500/20 text-green-400 text-sm rounded-full border border-green-500/30">
                  ● All Systems Operational
                </span>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-4 gap-4">
              <StatCard label="Total Users" value="12,847" change="+12.5%" icon="👥" />
              <StatCard label="API Requests" value="2.4M" change="+8.2%" icon="🔌" />
              <StatCard label="Avg Response" value="142ms" change="-5.1%" icon="⚡" />
              <StatCard label="Uptime" value="99.9%" change="+0.1%" icon="🟢" />
            </div>

            {/* Main Cards Grid */}
            <div className="grid grid-cols-2 gap-6">
              <DemoCard 
                title="System Health"
                action={
                  <span className="text-xs text-green-400">Real-time</span>
                }
              >
                <div className="space-y-2">
                  <SystemStatus name="API Gateway" status="healthy" details="Latency: 12ms" />
                  <SystemStatus name="Database" status="healthy" details="Connections: 156/500" />
                  <SystemStatus name="Cache Layer" status="warning" details="Hit rate: 87%" />
                  <SystemStatus name="Queue Workers" status="healthy" details="Processing: 42/s" />
                </div>
              </DemoCard>

              <DemoCard 
                title="Recent Activity"
                action={
                  <button className="text-xs text-[#10a37f] hover:text-[#0d8a6a]">View All</button>
                }
              >
                <div className="space-y-3">
                  {[
                    { time: "2m ago", event: "New deployment completed", status: "success" },
                    { time: "15m ago", event: "Cache optimized", status: "info" },
                    { time: "1h ago", event: "User spike detected", status: "warning" },
                    { time: "3h ago", event: "Database backup finished", status: "success" },
                  ].map((item, i) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-lg hover:bg-[#0d0d0d]">
                      <div className={`w-2 h-2 rounded-full ${
                        item.status === "success" ? "bg-green-500" :
                        item.status === "warning" ? "bg-yellow-500" : "bg-blue-500"
                      }`} />
                      <div className="flex-1">
                        <p className="text-white text-sm">{item.event}</p>
                        <p className="text-gray-500 text-xs">{item.time}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </DemoCard>

              <DemoCard title="Traffic Overview">
                <MiniChart data={[45, 62, 38, 85, 72, 90, 55, 78, 62, 95, 68, 82]} label="24h" />
              </DemoCard>

              <DemoCard title="Quick Actions">
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: "Deploy", icon: "🚀" },
                    { label: "Scale", icon: "📈" },
                    { label: "Monitor", icon: "👁️" },
                    { label: "Settings", icon: "⚙️" },
                  ].map((action, i) => (
                    <button
                      key={i}
                      className="p-4 bg-[#0d0d0d] rounded-xl border border-[#2a2a4e] hover:border-[#10a37f] transition-colors group"
                    >
                      <span className="text-2xl mb-2 block">{action.icon}</span>
                      <span className="text-white text-sm group-hover:text-[#10a37f] transition-colors">
                        {action.label}
                      </span>
                    </button>
                  ))}
                </div>
              </DemoCard>
            </div>
          </div>
        )}

        {activeTab === "chat" && (
          <div className="h-[calc(100vh-0px)]">
            <ChatInterface />
          </div>
        )}

        {activeTab === "analytics" && (
          <div className="p-6">
            <h2 className="text-2xl font-bold text-white mb-6">Analytics</h2>
            <div className="grid grid-cols-2 gap-6">
              <DemoCard title="User Growth">
                <MiniChart data={[30, 45, 55, 60, 75, 85, 95, 100, 120, 135, 150, 180]} label="12m" />
              </DemoCard>
              <DemoCard title="Revenue">
                <MiniChart data={[80, 75, 90, 85, 100, 95, 110, 105, 120, 115, 130, 150]} label="12m" />
              </DemoCard>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

// ============ PAGE EXPORT ============

export default function TamboDemoPage() {
  return (
    <TamboProvider
      apiKey={process.env.NEXT_PUBLIC_TAMBO_API_KEY!}
      components={tamboComponents}
    >
      <Dashboard />
    </TamboProvider>
  );
}
