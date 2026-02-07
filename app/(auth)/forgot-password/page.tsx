"use client";

import { useState } from "react";
import Link from "next/link";
import { createClient } from "@/lib/supabase-client";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setMessage("");

    try {
      const { error } = await createClient().auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/update-password`,
      });

      if (error) {
        setError(error.message);
      } else {
        setMessage("Check your email for a password reset link.");
      }
    } catch (err) {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md">
      {/* Logo */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-[#1a1a1a] border border-[#2a2a2a] mb-4">
          <svg className="w-7 h-7 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
          </svg>
        </div>
        <h1 className="text-2xl font-bold text-white">Reset password</h1>
        <p className="text-[#737373] mt-2">We'll send you a reset link</p>
      </div>

      {/* Reset Form */}
      <form onSubmit={handleResetPassword} className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-xl p-8">
        {error && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm">
            {error}
          </div>
        )}

        {message && (
          <div className="bg-[#10a37f]/10 border border-[#10a37f]/20 text-[#10a37f] px-4 py-3 rounded-lg mb-4 text-sm">
            {message}
          </div>
        )}

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Email address
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full bg-[#262626] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-[#737373] focus:outline-none focus:border-[#10a37f] focus:ring-1 focus:ring-[#10a37f]/20 transition-all"
            placeholder="you@example.com"
            required
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-gradient-to-r from-[#10a37f] to-[#0d8a6a] hover:from-[#0d8a6a] hover:to-[#10a37f] text-white font-semibold py-3 rounded-lg mt-6 transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Sending...
            </>
          ) : (
            "Send reset link"
          )}
        </button>
      </form>

      {/* Back to Login */}
      <p className="text-center text-[#737373] mt-6">
        <Link href="/login" className="text-[#10a37f] hover:text-[#0d8a6a] font-medium transition-colors">
          Back to sign in
        </Link>
      </p>
    </div>
  );
}
