"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase-client";

export default function SignupPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  // Check if user is already logged in
  useEffect(() => {
    const checkAuth = async () => {
      const { data: { user } } = await createClient().auth.getUser(); 
      if (user) {
        router.push("/security");
      }
    };
    checkAuth();
  }, [router]);

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const { error } = await createClient().auth.signUp({
        email,
        password,
      });

      if (error) {
        setError(error.message);
      } else {
        // Check if email confirmation is required
        const { data: { user } } = await createClient().auth.getUser();
        if (user) {
          // User is automatically signed in, redirect to security page
          router.push("/security");
        } else {
          setSuccess(true);
        }
      }
    } catch (err) {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-[#1a1a1a] border border-[#2a2a2a] mb-4">
            <svg className="w-7 h-7 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white">Check your email</h1>
          <p className="text-[#737373] mt-2">We&apos;ve sent you a confirmation link</p>
        </div>

        <div className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-xl p-8 text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#10a37f]/20 flex items-center justify-center">
            <svg className="w-8 h-8 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <p className="text-gray-300 mb-6">
            Please check your email <span className="text-white font-medium">{email}</span> and click the confirmation link to activate your account.
          </p>
          <Link 
            href="/login" 
            className="text-[#10a37f] hover:text-[#0d8a6a] font-medium transition-colors"
          >
            Go to Sign In
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-md">
      {/* Logo */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-[#1a1a1a] border border-[#2a2a2a] mb-4">
          <svg className="w-7 h-7 text-[#10a37f]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
        <h1 className="text-2xl font-bold text-white">Create an account</h1>
        <p className="text-[#737373] mt-2">Start your AI Chat journey</p>
      </div>

      {/* Signup Form */}
      <form onSubmit={handleSignup} className="bg-[#1a1a1a] border border-[#2a2a2a] rounded-xl p-8">
        {error && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm">
            {error}
          </div>
        )}

        <div className="mb-4">
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

        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-[#262626] border border-[#2a2a2a] rounded-lg px-4 py-3 text-white placeholder-[#737373] focus:outline-none focus:border-[#10a37f] focus:ring-1 focus:ring-[#10a37f]/20 transition-all"
            placeholder="••••••••"
            required
            minLength={6}
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-gradient-to-r from-[#10a37f] to-[#0d8a6a] hover:from-[#0d8a6a] hover:to-[#10a37f] text-white font-semibold py-3 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Creating account...
            </>
          ) : (
            "Create account"
          )}
        </button>
      </form>

      {/* Back to Login */}
      <p className="text-center text-[#737373] mt-6">
        Already have an account?{" "}
        <Link href="/login" className="text-[#10a37f] hover:text-[#0d8a6a] font-medium transition-colors">
          Sign in
        </Link>
      </p>
    </div>
  );
}
