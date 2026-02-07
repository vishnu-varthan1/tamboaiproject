"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "./components/AuthProvider";
import ChatInterface from "./components/ChatInterface";
import ChatHistory from "./components/ChatHistory";
import { createClient } from "@/lib/supabase-client";
import Link from "next/link";
import K8sDashboard from "./components/k8s/K8sDashboard";
import { TamboProvider, useTamboThread, useTamboThreadInput } from "@tambo-ai/react";
import { tamboComponents } from "./components/tambo/TamboComponents";

type ModelType = "tambo-ai" | "gpt-4" | "claude-3";

interface UserProfile {
  email: string;
  plan: "free" | "pro" | "enterprise";
}

// ============ TAMBO CHAT COMPONENT ============

function TamboChatInterface() {
  const { thread } = useTamboThread();
  const { value, setValue, submit, isPending } = useTamboThreadInput();

  const formatContent = (content: unknown): React.ReactNode => {
    if (typeof content === "string") {
      // Check if content looks like JSON (Tambo generative UI)
      if (content.trim().startsWith("{")) {
        try {
          const parsed = JSON.parse(content);
          return <pre className="text-xs bg-[#0d0d0d] p-2 rounded mt-2 overflow-x-auto">{JSON.stringify(parsed, null, 2)}</pre>;
        } catch {
          return <p className="text-sm">{content}</p>;
        }
      }
      return <p className="text-sm">{content}</p>;
    }
    if (Array.isArray(content)) {
      return content.map((c, i) => (
        <p key={i} className="text-sm">{c?.text}</p>
      ));
    }
    return <p className="text-sm">{String(content)}</p>;
  };

  return (
    <div className="h-full flex flex-col bg-[#0d0d0d]">
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {thread?.messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center py-12">
            <div className="w-20 h-20 rounded-2xl bg-[#10a37f]/10 border border-[#10a37f]/20 flex items-center justify-center mx-auto mb-6">
              <svg className="w-10 h-10 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <h3 className="text-xl font-bold text-white mb-2">EVS AI Assistant</h3>
            <p className="text-gray-400 text-sm max-w-md mx-auto mb-6">
              AI-driven threat detection, vulnerability analysis, and automated response for modern SecOps teams.
            </p>
            <div className="flex flex-wrap justify-center gap-2">
              {[
                "Analyze security vulnerabilities",
                "Show threat intelligence",
                "Display compliance status",
                "List recent incidents",
              ].map((suggestion, i) => (
                <button
                  key={i}
                  onClick={() => setValue(suggestion)}
                  className="px-4 py-2 bg-[#1a1a2e] border border-[#2a2a4e] rounded-lg text-sm text-gray-300 hover:border-[#10a37f] hover:text-white transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        ) : (
          thread?.messages.map((message, i) => (
            <div
              key={i}
              className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-[85%] rounded-2xl px-5 py-3 ${
                  message.role === 'user'
                    ? 'bg-[#10a37f] text-white'
                    : 'bg-[#1a1a2e] border border-[#2a2a4e] text-white'
                }`}
              >
                {message.content && formatContent(message.content)}
              </div>
            </div>
          ))
        )}
        {isPending && (
          <div className="flex justify-start">
            <div className="bg-[#1a1a2e] border border-[#2a2a4e] rounded-2xl px-4 py-3">
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
          className="flex gap-3"
        >
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Ask about security threats, vulnerabilities, or incidents..."
            className="flex-1 bg-[#0d0d0d] border border-[#2a2a4e] rounded-xl px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-[#10a37f]"
          />
          <button
            type="submit"
            disabled={isPending || !value.trim()}
            className="px-6 py-3 bg-[#10a37f] text-white rounded-xl font-medium hover:bg-[#0d8a6a] disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            <span>Send</span>
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </form>
      </div>
    </div>
  );
}

// ============ MAIN PAGE COMPONENT ============

export default function Home() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [currentModel, setCurrentModel] = useState<ModelType>("tambo-ai");
  const [showPricing, setShowPricing] = useState(false);
  const [currentChatId, setCurrentChatId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"chat" | "k8s">("chat");

  const userProfile: UserProfile = user ? {
    email: user.email || "User",
    plan: "free",
  } : null;

  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [user, loading, router]);

  const handleLogout = async () => {
    await createClient().auth.signOut();
    router.push("/login");
  };

  const handleSelectChat = (chatId: string) => {
    setCurrentChatId(chatId);
    setSidebarOpen(false);
  };

  const models = [
    { id: "tambo-ai", name: "Tambo AI", description: "Generative UI + Chat", icon: "🤖" },
    { id: "gpt-4", name: "GPT-4", description: "Most capable", icon: "⚡" },
    { id: "claude-3", name: "Claude 3", description: "Best for reasoning", icon: "🧠" },
  ];

  if (loading || !user) {
    return (
      <div className="min-h-screen bg-[#0d0d0d] flex items-center justify-center p-4">
        <div className="text-center">
          <div className="w-16 h-16 rounded-2xl bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center mx-auto animate-pulse">
            <svg className="w-8 h-8 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
          </div>
          <p className="text-gray-400 mt-4">Loading EVS Security Operations...</p>
        </div>
      </div>
    );
  }

  return (
    <TamboProvider
      apiKey={process.env.NEXT_PUBLIC_TAMBO_API_KEY || "demo-key"}
      components={tamboComponents}
    >
      <div className="min-h-screen bg-[#0d0d0d] flex">
        {/* Mobile sidebar backdrop */}
        {sidebarOpen && (
          <div 
            className="fixed inset-0 bg-black/50 z-40 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Sidebar */}
        <aside className={`fixed sm:relative inset-y-0 left-0 z-50 w-72 sm:w-64 bg-[#171717] border-r border-[#2a2a2a] transform transition-transform duration-300 ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full sm:translate-x-0"
        }`}>
          <div className="flex flex-col h-full">
            {/* Logo */}
            <div className="p-4 border-b border-[#2a2a2a]">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center flex-shrink-0">
                  <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <div className="min-w-0">
                  <h1 className="font-semibold text-white truncate">EVS</h1>
                  <p className="text-xs text-[#737373] truncate">Security Operations Powered by Tambo AI</p>
                </div>
              </div>
            </div>

            {/* Tab Navigation */}
            <div className="px-4 py-3 border-b border-[#2a2a2a]">
              <div className="flex gap-1 bg-[#262626] p-1 rounded-lg">
                <button
                  onClick={() => setActiveTab("chat")}
                  className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === "chat"
                      ? "bg-[#1a1a1a] text-white shadow"
                      : "text-gray-400 hover:text-white"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                  </svg>
                  <span className="hidden sm:inline">Chat</span>
                </button>
                <a
                  href="/security"
                  className="flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors text-gray-400 hover:text-white hover:bg-[#262626]"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                  <span className="hidden sm:inline">SecOps</span>
                </a>
                <button
                  onClick={() => setActiveTab("k8s")}
                  className={`flex-1 flex items-center justify-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === "k8s"
                      ? "bg-[#1a1a1a] text-white shadow"
                      : "text-gray-400 hover:text-white"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
                  </svg>
                  <span className="hidden sm:inline">K8s</span>
                </button>
              </div>
            </div>

            {/* Chat History */}
            <ChatHistory onSelectChat={handleSelectChat} currentChatId={currentChatId} />

            {/* Model Selection */}
            <div className="px-4 py-4 border-t border-[#2a2a2a]">
              <p className="text-xs text-[#737373] uppercase tracking-wider mb-2">Model</p>
              <div className="space-y-1">
                {models.map((model) => (
                  <button
                    key={model.id}
                    onClick={() => setCurrentModel(model.id as ModelType)}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors ${
                      currentModel === model.id 
                        ? "bg-[#2a2a2a] text-white" 
                        : "text-gray-300 hover:bg-[#262626]"
                    }`}
                  >
                    <span className="text-lg flex-shrink-0">{model.icon}</span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{model.name}</p>
                      <p className="text-xs text-[#737373] truncate">{model.description}</p>
                    </div>
                    {model.id !== "tambo-ai" && userProfile?.plan !== "pro" && userProfile?.plan !== "enterprise" && (
                      <svg className="w-4 h-4 text-[#737373] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Upgrade Card */}
            <div className="mx-4 mb-4 p-4 bg-gradient-to-br from-[#10a37f]/10 to-[#1a1a1a] border border-[#10a37f]/20 rounded-xl">
              <div className="flex items-center gap-2 mb-2">
                <svg className="w-5 h-5 text-[#10a37f] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
                </svg>
                <span className="font-medium text-white">Upgrade to Pro</span>
              </div>
              <p className="text-xs text-gray-400 mb-3">Get access to GPT-4, Claude 3, and Tambo AI Pro features.</p>
              <button 
                onClick={() => setShowPricing(true)}
                className="w-full bg-[#10a37f] hover:bg-[#0d8a6a] text-white text-sm font-medium py-2 rounded-lg btn-transition"
              >
                View Plans
              </button>
            </div>

            {/* User Section */}
            <div className="mt-auto p-4 border-t border-[#2a2a2a]">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-9 h-9 rounded-full bg-[#10a37f] flex items-center justify-center text-white text-sm font-medium flex-shrink-0">
                  {(userProfile?.email || "U").substring(0, 2).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">{userProfile?.email?.split("@")[0] || "User"}</p>
                  <p className="text-xs text-[#737373] capitalize">{userProfile?.plan || "Free"} Plan</p>
                </div>
              </div>
              <div className="space-y-1">
                <Link 
                  href="/settings"
                  className="flex items-center gap-2 px-3 py-2 text-gray-300 hover:bg-[#262626] rounded-lg text-sm transition-colors"
                >
                  <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                  <span className="truncate">Settings</span>
                </Link>
                <button 
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2 px-3 py-2 text-gray-300 hover:bg-[#262626] rounded-lg text-sm transition-colors"
                >
                  <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                  </svg>
                  <span className="truncate">Log out</span>
                </button>
              </div>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col h-screen min-w-0 overflow-hidden">
          {/* Mobile Header */}
          <header className="flex sm:hidden items-center gap-3 p-4 border-b border-[#2a2a2a]">
            <button 
              onClick={() => setSidebarOpen(true)}
              className="p-2 text-gray-300 hover:text-white"
              aria-label="Open menu"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <div className="flex-1">
              <h1 className="font-semibold text-white">
                {activeTab === "k8s" ? "Kubernetes Dashboard" : "EVS AI Assistant — Powered by Tambo AI"}
              </h1>
            </div>
          </header>

          {/* Content based on active tab */}
          {activeTab === "chat" ? (
            currentModel === "tambo-ai" ? (
              <TamboChatInterface />
            ) : (
              <ChatInterface />
            )
          ) : (
            <K8sDashboard />
          )}
        </main>

        {/* Pricing Modal */}
        {showPricing && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4" onClick={() => setShowPricing(false)}>
            <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
              <div className="p-6 border-b border-[#2a2a2a] flex items-center justify-between sticky top-0 bg-[#1a1a1a]">
                <h2 className="text-xl font-semibold text-white">Choose Your Plan</h2>
                <button onClick={() => setShowPricing(false)} className="text-gray-400 hover:text-white">
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <div className="p-6 grid sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
                {/* Free Plan */}
                <div className="p-6 bg-[#262626] rounded-xl">
                  <h3 className="text-lg font-semibold text-white mb-2">Free</h3>
                  <p className="text-3xl font-bold text-white mb-4">$0<span className="text-sm text-gray-400 font-normal">/mo</span></p>
                  <ul className="space-y-3 mb-6 text-sm text-gray-300">
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      Tambo AI access
                    </li>
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      Standard speed
                    </li>
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      20 msgs/day
                    </li>
                  </ul>
                  <button className="w-full py-2.5 border border-[#404040] text-gray-300 rounded-lg hover:bg-[#262626] transition-colors">
                    Current
                  </button>
                </div>

                {/* Pro Plan */}
                <div className="p-6 bg-gradient-to-b from-[#10a37f]/10 to-transparent border border-[#10a37f]/30 rounded-xl relative">
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-[#10a37f] text-white text-xs font-medium px-3 py-1 rounded-full">
                    Popular
                  </div>
                  <h3 className="text-lg font-semibold text-white mb-2">Pro</h3>
                  <p className="text-3xl font-bold text-white mb-4">$19<span className="text-sm text-gray-400 font-normal">/mo</span></p>
                  <ul className="space-y-3 mb-6 text-sm text-gray-300">
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      <span className="text-white">All Free +</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      <span className="text-white">GPT-4, Claude 3</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      <span className="text-white">Unlimited msgs</span>
                    </li>
                  </ul>
                  <button className="w-full py-2.5 bg-[#10a37f] hover:bg-[#0d8a6a] text-white rounded-lg font-medium btn-transition">
                    Upgrade
                  </button>
                </div>

                {/* Enterprise Plan */}
                <div className="p-6 bg-[#262626] rounded-xl sm:col-span-2 lg:col-span-1">
                  <h3 className="text-lg font-semibold text-white mb-2">Enterprise</h3>
                  <p className="text-3xl font-bold text-white mb-4">$99<span className="text-sm text-gray-400 font-normal">/mo</span></p>
                  <ul className="space-y-3 mb-6 text-sm text-gray-300">
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      <span className="text-white">All Pro features</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      <span className="text-white">Custom models</span>
                    </li>
                    <li className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-[#10a37f] flex-shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                      <span className="text-white">API access</span>
                    </li>
                  </ul>
                  <button className="w-full py-2.5 border border-[#404040] text-gray-300 hover:bg-[#262626] rounded-lg transition-colors">
                    Contact
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </TamboProvider>
  );
}
