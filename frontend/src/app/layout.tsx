import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RippleGuard — Supply-Chain Risk Intelligence",
  description: "AI-powered open-source software supply-chain risk intelligence platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="flex min-h-screen flex-col bg-slate-950 text-slate-100 antialiased selection:bg-blue-600 selection:text-white">
        <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3.5 sm:px-6">
            <div className="flex items-center space-x-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600 font-bold text-white shadow-lg shadow-blue-500/20">
                RG
              </div>
              <span className="font-semibold tracking-tight text-white text-lg">
                RippleGuard
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="inline-flex items-center rounded-full bg-blue-500/10 px-2.5 py-1 text-xs font-medium text-blue-400 ring-1 ring-inset ring-blue-500/20">
                Phase 1: Foundation
              </span>
            </div>
          </div>
        </header>

        <main className="flex-1">
          {children}
        </main>

        <footer className="border-t border-slate-800/80 bg-slate-950 py-6 text-center text-xs text-slate-500">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <p>RippleGuard &bull; Open-Source Supply-Chain Risk Intelligence Platform</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
