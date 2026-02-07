"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "./AuthProvider";

export default function Header() {
  const { user, loading } = useAuth();
  const pathname = usePathname();

  // Hide header on main chat page and security page since they have their own navigation
  if (pathname === "/" || pathname === "/security") {
    return null;
  }

  if (loading) {
    return (
      <header className="bg-[#0d0d0d] border-b border-[#2a2a2a]">
        <div className="max-w-5xl mx-auto px-4 py-4 flex justify-between items-center">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center">
              <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
            </div>
            <span className="font-semibold text-white">EVS</span>
          </Link>
          <span className="hidden sm:inline text-xs text-[#10a37f] ml-1">— Security Operations Powered by Tambo AI</span>
          <div className="w-8 h-8 bg-[#1a1a1a] rounded-full animate-pulse" />
        </div>
      </header>
    );
  }

  return (
    <header className="bg-[#0d0d0d] border-b border-[#2a2a2a]">
      <div className="max-w-5xl mx-auto px-4 py-4 flex justify-between items-center">
        <Link href="/" className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-[#1a1a1a] border border-[#2a2a2a] flex items-center justify-center">
            <svg className="w-5 h-5 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
          </div>
          <span className="font-semibold text-white">EVS</span>
        </Link>
        
        {user ? (
          <Link
            href="/"
            className="px-4 py-2 bg-[#10a37f] hover:bg-[#0d8a6a] text-white text-sm font-medium rounded-lg transition-colors"
          >
            Go to Chat
          </Link>
        ) : (
          <div className="flex items-center gap-3">
            <Link
              href="/login"
              className="px-4 py-2 text-[#737373] hover:text-white text-sm font-medium transition-colors"
            >
              Sign in
            </Link>
            <Link
              href="/signup"
              className="px-4 py-2 bg-[#10a37f] hover:bg-[#0d8a6a] text-white text-sm font-medium rounded-lg transition-colors"
            >
              Sign up
            </Link>
          </div>
        )}
      </div>
    </header>
  );
}
