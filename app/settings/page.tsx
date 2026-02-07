"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../components/AuthProvider";
import { useTheme } from "../components/ThemeProvider";
import { createClient } from "@/lib/supabase-client";
import { TamboProvider } from "@tambo-ai/react";
import { tamboComponents } from "@/app/components/tambo/TamboComponents";

type Theme = "dark" | "light" | "system";

interface AISettings {
  temperature: number;
  maxTokens: number;
  systemPrompt: string;
  model: string;
}

// ============ SETTINGS CONTENT COMPONENT ============

function SettingsContent() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const [aiSettings, setAiSettings] = useState<AISettings>({
    temperature: 0.7,
    maxTokens: 4096,
    systemPrompt: "You are a helpful AI assistant.",
    model: "tambo-ai",
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [user, loading, router]);

  useEffect(() => {
    const savedSettings = localStorage.getItem("aiSettings");
    if (savedSettings) {
      setAiSettings(JSON.parse(savedSettings));
    }
  }, []);

  const handleSaveAI = async () => {
    setSaving(true);
    localStorage.setItem("aiSettings", JSON.stringify(aiSettings));
    await new Promise((resolve) => setTimeout(resolve, 500));
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleThemeChange = (newTheme: Theme) => {
    setTheme(newTheme);
  };

  const handleReset = () => {
    setAiSettings({
      temperature: 0.7,
      maxTokens: 4096,
      systemPrompt: "You are a helpful AI assistant.",
      model: "tambo-ai",
    });
  };

  if (loading || !user) {
    return (
      <div className="min-h-screen bg-[#0d0d0d] flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 rounded-2xl bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center mx-auto animate-pulse">
            <svg className="w-8 h-8 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <p className="text-gray-400 mt-4">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0d0d0d]">
      {/* Header */}
      <header className="bg-[#0d0d0d] border-b border-[#2a2a2e]">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center gap-4">
          <Link 
            href="/"
            className="p-2 text-gray-300 hover:text-white rounded-lg hover:bg-[#1a1a2e] transition-colors"
            aria-label="Back to chat"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
          </Link>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center">
              <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-semibold text-white">Settings</h1>
              <p className="text-xs text-gray-500">Manage your preferences</p>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-4 py-8 space-y-8">
        {/* Theme Settings */}
        <section>
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01" />
            </svg>
            Appearance
          </h2>
          <div className="bg-[#1a1a1a] border border-[#2a2a2e] rounded-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <p className="text-white font-medium">Theme</p>
                <p className="text-sm text-gray-500">Choose your preferred theme</p>
              </div>
              <span className="px-3 py-1 bg-[#262626] rounded-full text-sm text-gray-300 capitalize border border-[#2a2a2a]">
                {theme}
              </span>
            </div>
            <div className="grid grid-cols-3 gap-4">
              {[
                { id: "dark", label: "Dark", icon: "🌙", desc: "Always dark mode" },
                { id: "light", label: "Light", icon: "☀️", desc: "Always light mode" },
                { id: "system", label: "System", icon: "💻", desc: "Match system setting" },
              ].map((option) => (
                <button
                  key={option.id}
                  onClick={() => handleThemeChange(option.id as Theme)}
                  className={`p-4 rounded-xl border-2 transition-all text-left ${
                    theme === option.id
                      ? "border-[#10a37f] bg-[#1a1a2e]"
                      : "border-[#2a2a2e] hover:border-[#3a3a4e] bg-[#0d0d0d]"
                  }`}
                >
                  <div className="text-2xl mb-3">{option.icon}</div>
                  <p className="text-white text-sm font-medium">{option.label}</p>
                  <p className="text-xs text-gray-500">{option.desc}</p>
                </button>
              ))}
            </div>
          </div>
        </section>

        {/* Advanced AI Settings */}
        <section>
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            AI Settings
          </h2>
          <div className="bg-[#1a1a1a] border border-[#2a2a2e] rounded-xl p-6 space-y-6">
            {/* Model Selection */}
            <div>
              <label className="block text-white font-medium mb-2">AI Model</label>
              <select
                value={aiSettings.model}
                onChange={(e) => setAiSettings({ ...aiSettings, model: e.target.value })}
                className="w-full bg-[#262626] border border-[#2a2a2a] text-white rounded-lg px-4 py-3 focus:outline-none focus:border-[#10a37f]"
              >
                <option value="tambo-ai">🤖 Tambo AI (Default)</option>
                <option value="gpt-4">⚡ GPT-4 (Pro)</option>
                <option value="claude-3">🧠 Claude 3 (Pro)</option>
              </select>
              <p className="text-xs text-gray-500 mt-1">Select which AI model to use for responses</p>
            </div>

            {/* Temperature */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-white font-medium">Temperature</label>
                <span className="px-2 py-1 bg-[#262626] rounded text-sm text-gray-300 font-mono">
                  {aiSettings.temperature.toFixed(1)}
                </span>
              </div>
              <input
                type="range"
                min="0"
                max="2"
                step="0.1"
                value={aiSettings.temperature}
                onChange={(e) => setAiSettings({ ...aiSettings, temperature: parseFloat(e.target.value) })}
                className="w-full h-2 bg-[#262626] rounded-lg appearance-none cursor-pointer accent-[#10a37f]"
              />
              <div className="flex justify-between text-xs text-gray-500 mt-2">
                <span>More focused</span>
                <span>More creative</span>
              </div>
            </div>

            {/* Max Tokens */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-white font-medium">Max Tokens</label>
                <span className="px-2 py-1 bg-[#262626] rounded text-sm text-gray-300 font-mono">
                  {aiSettings.maxTokens.toLocaleString()}
                </span>
              </div>
              <input
                type="range"
                min="512"
                max="16384"
                step="512"
                value={aiSettings.maxTokens}
                onChange={(e) => setAiSettings({ ...aiSettings, maxTokens: parseInt(e.target.value) })}
                className="w-full h-2 bg-[#262626] rounded-lg appearance-none cursor-pointer accent-[#10a37f]"
              />
              <div className="flex justify-between text-xs text-gray-500 mt-2">
                <span>Shorter responses</span>
                <span>Longer responses</span>
              </div>
            </div>

            {/* System Prompt */}
            <div>
              <label className="block text-white font-medium mb-2">System Prompt</label>
              <textarea
                value={aiSettings.systemPrompt}
                onChange={(e) => setAiSettings({ ...aiSettings, systemPrompt: e.target.value })}
                rows={4}
                className="w-full bg-[#262626] border border-[#2a2a2a] text-white rounded-lg px-4 py-3 focus:outline-none focus:border-[#10a37f] resize-none"
                placeholder="Enter a system prompt to define the AI's behavior..."
              />
              <p className="text-xs text-gray-500 mt-1">Define how the AI should behave in conversations</p>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-4 pt-4 border-t border-[#2a2a2a]">
              <button
                onClick={handleSaveAI}
                disabled={saving}
                className="flex items-center gap-2 bg-[#10a37f] hover:bg-[#0d8a6a] disabled:bg-[#404040] text-white px-6 py-2.5 rounded-lg font-medium transition-colors"
              >
                {saving ? (
                  <>
                    <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Saving...
                  </>
                ) : saved ? (
                  <>
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    Saved!
                  </>
                ) : (
                  <>
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    Save Settings
                  </>
                )}
              </button>
              <button
                onClick={handleReset}
                className="text-gray-400 hover:text-white text-sm transition-colors"
              >
                Reset to defaults
              </button>
            </div>
          </div>
        </section>

        {/* Account Info */}
        <section>
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            Account
          </h2>
          <div className="bg-[#1a1a1a] border border-[#2a2a2e] rounded-xl p-6">
            <div className="flex items-center gap-4 mb-6">
              <div className="w-14 h-14 rounded-xl bg-[#10a37f] flex items-center justify-center text-white text-lg font-medium">
                {(user.email || "U").substring(0, 2).toUpperCase()}
              </div>
              <div className="flex-1">
                <p className="text-white font-medium">{user.email}</p>
                <p className="text-sm text-gray-500">Free Plan</p>
              </div>
              <span className="px-3 py-1 bg-[#10a37f]/10 text-[#10a37f] text-xs font-medium rounded-full border border-[#10a37f]/20">
                Verified
              </span>
            </div>
            <div className="flex flex-wrap gap-4">
              <button className="flex items-center gap-2 px-4 py-2 bg-[#262626] hover:bg-[#2a2a2a] text-gray-300 rounded-lg text-sm transition-colors border border-[#2a2a2a]">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
                Change Password
              </button>
              <button className="flex items-center gap-2 px-4 py-2 bg-[#262626] hover:bg-[#2a2a2a] text-gray-300 rounded-lg text-sm transition-colors border border-[#2a2a2a]">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                </svg>
                Upload Avatar
              </button>
              <button className="flex items-center gap-2 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg text-sm transition-colors border border-red-500/20 ml-auto">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                Delete Account
              </button>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

// ============ PAGE EXPORT ============

export default function SettingsPage() {
  return (
    <TamboProvider
      apiKey={process.env.NEXT_PUBLIC_TAMBO_API_KEY || "demo-key"}
      components={tamboComponents}
    >
      <SettingsContent />
    </TamboProvider>
  );
}
