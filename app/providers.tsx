"use client";

import { TamboProvider } from "@tambo-ai/react";
import { ThemeProvider } from "./components/ThemeProvider";
import { tamboComponents } from "./components/tambo/TamboComponents";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <TamboProvider 
      apiKey={process.env.NEXT_PUBLIC_TAMBO_API_KEY!}
      components={tamboComponents}
    >
      <ThemeProvider>
        {children}
      </ThemeProvider>
    </TamboProvider>
  );
}
