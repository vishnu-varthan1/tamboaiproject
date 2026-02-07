"use client";

import { TamboProvider } from "@tambo-ai/react";
import { tamboComponents } from "@/app/components/tambo/TamboComponents";

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <TamboProvider
      apiKey={process.env.NEXT_PUBLIC_TAMBO_API_KEY || "demo-key"}
      components={tamboComponents}
    >
      <div className="min-h-screen w-full flex flex-col bg-black relative">
        {/* Tambo AI Animated Background */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-[#10a37f]/5 rounded-full blur-3xl animate-pulse" />
          <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-[#1a1a2e]/30 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }} />
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-[#0d0d0d]/50 rounded-full blur-3xl" />
        </div>

        {/* Grid Pattern Overlay */}
        <div className="absolute inset-0 opacity-10" style={{
          backgroundImage: `linear-gradient(rgba(16, 163, 127, 0.15) 1px, transparent 1px),
            linear-gradient(90deg, rgba(16, 163, 127, 0.15) 1px, transparent 1px)`,
          backgroundSize: '60px 60px'
        }} />

        {/* Main Content - Centered */}
        <main className="flex-1 flex items-center justify-center relative z-10 px-4 py-8">
          {children}
        </main>
      </div>
    </TamboProvider>
  );
}
