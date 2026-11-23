import React, { useState } from 'react';
import { ArrowRight, Lock, ShieldCheck, Terminal } from 'lucide-react';
import { useGodWorkspace } from '../context/GodWorkspaceContext';
import { NeuralCoreOrb } from './NeuralCoreOrb';
import { GOD_CORE_MODEL, GOD_CORE_VERSION } from '../shared/godCoreLogic';

export const AuthGate: React.FC = () => {
  const { signInWithGoogle, enterPreviewMode, authError } = useGodWorkspace();
  const [signingIn, setSigningIn] = useState(false);
  const [heroImgFailed, setHeroImgFailed] = useState(false);

  const handleGoogleLogin = async () => {
    setSigningIn(true);
    try {
      await signInWithGoogle();
    } finally {
      setSigningIn(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090b10] text-slate-100 flex flex-col">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 lg:px-10 py-4 border-b border-white/[0.08]">
        <a
          href="#top"
          className="text-lg font-bold tracking-tight text-white font-display whitespace-nowrap shrink-0"
        >
          AI GOD (GOD-X)
        </a>

        <nav
          aria-label="Platform overview"
          className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400"
        >
          <a
            href="#architecture"
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Architecture
          </a>
          <a
            href="#agents"
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Agent Registry
          </a>
          <a
            href="#security"
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Zero-Trust Rules
          </a>
          <a
            href="#hybrid"
            className="hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            Hybrid Bridge
          </a>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={handleGoogleLogin}
            disabled={signingIn}
            className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-60 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {signingIn ? 'Authenticating...' : 'Sign in with Google'}
          </button>
        </div>
      </header>

      <main id="top" className="flex-1 max-w-6xl w-full mx-auto px-6 lg:px-10 py-12 lg:py-16 space-y-16">
        {/* Hero Split */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-stretch">
          <div className="lg:col-span-7 flex flex-col justify-between space-y-8">
            <div className="space-y-5">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400 tabular-nums">
                <span>Release v{GOD_CORE_VERSION}</span>
                <span aria-hidden="true">·</span>
                <span>Server Engine: {GOD_CORE_MODEL}</span>
                <span aria-hidden="true">·</span>
                <span>Cloud Firestore Isolated</span>
              </div>

              <h1 className="text-3xl sm:text-4xl lg:text-[44px] font-bold tracking-tight text-white leading-[1.12]">
                Modular Multi-Agent Personal Intelligence Command Center
              </h1>

              <p className="text-base text-slate-300 leading-relaxed max-w-2xl">
                Chat, reason, synthesize research, manage operational tasks, and audit capability
                approvals through a server-protected Gemini core backed by tenant-isolated Cloud
                Firestore memory.
              </p>
            </div>

            {authError && (
              <div
                role="alert"
                className="p-3.5 rounded-lg border border-red-500/35 bg-red-950/25 text-sm text-red-200"
              >
                {authError}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-4 pt-1">
              <button
                type="button"
                onClick={handleGoogleLogin}
                disabled={signingIn}
                className="inline-flex items-center gap-2.5 px-5 py-2.5 text-sm font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <span>{signingIn ? 'Signing in...' : 'Sign in with Google'}</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <button
                type="button"
                onClick={enterPreviewMode}
                className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-medium bg-[#131824] hover:bg-[#1a2131] text-slate-200 border border-white/[0.1] rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <span>Inspect Preview Workspace</span>
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Google Sign-In provisions your private Cloud Firestore namespace and authenticates
              server-side Gemini streaming. Preview Workspace opens an isolated local-memory tour.
            </p>
          </div>

          <div className="lg:col-span-5 relative rounded-xl border border-white/[0.08] bg-[#0f131c] overflow-hidden min-h-[320px] flex flex-col items-center justify-center p-8">
            {!heroImgFailed && (
              <img
                src="/src/assets/images/god_core_backdrop_1795262096906.jpg"
                alt="Anodized obsidian hardware command surface"
                referrerPolicy="no-referrer"
                onError={() => setHeroImgFailed(true)}
                className="absolute inset-0 w-full h-full object-cover opacity-35"
              />
            )}
            <div className="absolute inset-0 bg-gradient-to-t from-[#090b10] via-[#090b10]/65 to-transparent" />

            <div className="relative z-10 flex flex-col items-center text-center space-y-5">
              <NeuralCoreOrb emergencyStop={false} size="lg" />
              <div className="space-y-1">
                <p className="text-sm font-semibold text-white">GOD Core Neural Orchestrator</p>
                <p className="text-xs font-mono text-slate-400 tabular-nums">
                  Server-Only SDK · 0 Client Keys · 8-Pillar Firestore Rules
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Architectural Pillars */}
        <section
          id="architecture"
          className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-8 border-t border-white/[0.08]"
        >
          <div id="agents" className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.07] space-y-2.5">
            <div className="flex items-center gap-2 text-blue-400">
              <Terminal className="w-4 h-4 shrink-0" />
              <h2 className="text-base font-semibold text-white">Honest v0.1 Capability Routing</h2>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed">
              GOD Core classifies every prompt across Chat, Research, Coding, Vision, Security, and
              Automation—executing conversational reasoning via Gemini while transparently labeling
              v0.2 specialist modules.
            </p>
          </div>

          <div id="security" className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.07] space-y-2.5">
            <div className="flex items-center gap-2 text-red-400">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <h2 className="text-base font-semibold text-white">Zero-Trust Firestore & Guardrails</h2>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed">
              Conversations, tasks, split PII records, and immutable audit logs are strictly scoped
              to your authenticated UID, paired with an instant Emergency Stop kill-switch.
            </p>
          </div>

          <div id="hybrid" className="p-5 rounded-xl bg-[#0f131c] border border-white/[0.07] space-y-2.5">
            <div className="flex items-center gap-2 text-slate-300">
              <Lock className="w-4 h-4 shrink-0" />
              <h2 className="text-base font-semibold text-white">Staged Hybrid Node Architecture</h2>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed">
              Provider adapters prepare AI GOD for Windows and Kali Linux local Ollama nodes over
              authenticated outbound WSS tunnels—keeping local execution locked until paired.
            </p>
          </div>
        </section>
      </main>
    </div>
  );
};
