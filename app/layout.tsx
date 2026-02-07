"use client";
import { TamboProvider } from "@tambo-ai/react";
import { AuthProvider } from "./components/AuthProvider";
import Header from "./components/Header";
import "./globals.css";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-[#0a0a0f]" suppressHydrationWarning>
        <TamboProvider apiKey={process.env.NEXT_PUBLIC_TAMBO_API_KEY || ""}>
          <AuthProvider>
            <Header />
            {children}
          </AuthProvider>
        </TamboProvider>
      </body>
    </html>
  );
}
