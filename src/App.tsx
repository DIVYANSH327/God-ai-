/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Activity,
  Bot,
  BrainCircuit,
  Code2,
  Cpu,
  Database,
  Eye,
  Globe,
  LayoutDashboard,
  LogIn,
  Menu,
  MessageSquare,
  Mic,
  Network,
  OctagonAlert,
  Radar,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  Workflow,
  X,
} from 'lucide-react';
import { ErrorBoundary } from './components/ErrorBoundary';
import { AuthGate } from './components/AuthGate';
import { NeuralCoreOrb } from './components/NeuralCoreOrb';
import {
  GodWorkspaceProvider,
  useGodWorkspace,
} from './context/GodWorkspaceContext';
import { GinIntelligenceProvider } from './context/GinIntelligenceContext';
import { GriResearchProvider } from './context/GriResearchContext';
import { SentinelProvider } from './context/SentinelContext';
import { DashboardView } from './views/DashboardView';
import { SentinelView } from './views/SentinelView';
import { NetworkObserverView } from './views/NetworkObserverView';
import { InternetExplorerView } from './views/InternetExplorerView';
import { BehaviourEngineView } from './views/BehaviourEngineView';
import { KnowledgeGraphView } from './views/KnowledgeGraphView';
import { WebTechIntelView } from './views/WebTechIntelView';
import { ServerIntelView } from './views/ServerIntelView';
import { SecurityResearchView } from './views/SecurityResearchView';
import { ContinuousResearchView } from './views/ContinuousResearchView';
import { ChatView } from './views/ChatView';
import { AgentsView } from './views/AgentsView';
import {
  AutomationModuleView,
  VisionModuleView,
  VoiceModuleView,
} from './views/DomainModulesView';
import { MemoryView } from './views/MemoryView';
import { SecurityView } from './views/SecurityView';
import { SettingsView } from './views/SettingsView';
import type { NavSection } from './shared/types';

const NAV_ITEMS: ReadonlyArray<{
  id: NavSection;
  label: string;
  group: 'sentinel' | 'gri' | 'gin' | 'core';
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: 'sentinel', label: 'Sentinel Command', group: 'sentinel', icon: Shield },
  { id: 'dashboard', label: 'GOD Dashboard', group: 'gri', icon: LayoutDashboard },
  { id: 'research', label: 'Internet Explorer', group: 'gri', icon: Globe },
  { id: 'webintel', label: 'Web & Tech Intel', group: 'gri', icon: Code2 },
  { id: 'serverintel', label: 'Server Intel', group: 'gri', icon: Server },
  { id: 'cveintel', label: 'Security Research', group: 'gri', icon: ShieldAlert },
  { id: 'knowledge', label: 'Knowledge Graph', group: 'gri', icon: Network },
  { id: 'monitors', label: 'Continuous Research', group: 'gri', icon: Radar },
  { id: 'network', label: 'Network Observer', group: 'gin', icon: Activity },
  { id: 'behaviour', label: 'Behaviour Engine', group: 'gin', icon: BrainCircuit },
  { id: 'chat', label: 'AI Chat', group: 'core', icon: MessageSquare },
  { id: 'agents', label: 'Agents', group: 'core', icon: Bot },
  { id: 'vision', label: 'Vision', group: 'core', icon: Eye },
  { id: 'voice', label: 'Voice', group: 'core', icon: Mic },
  { id: 'memory', label: 'Memory', group: 'core', icon: Database },
  { id: 'security', label: 'Security Center', group: 'core', icon: Shield },
  { id: 'automation', label: 'Automation', group: 'core', icon: Workflow },
  { id: 'settings', label: 'Settings', group: 'core', icon: Settings },
];

const CommandCenterShell: React.FC = () => {
  const {
    authReady,
    firebaseUser,
    isPreviewMode,
    signInWithGoogle,
    exitPreviewMode,
    activeSection,
    setActiveSection,
    profile,
    isStreamingChat,
    toggleEmergencyStop,
  } = useGodWorkspace();

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  React.useEffect(() => {
    window.scrollTo(0, 0);
  }, [activeSection]);

  if (!authReady) {
    return (
      <div className="min-h-screen bg-[#090b10] text-slate-200 flex flex-col items-center justify-center gap-4">
        <NeuralCoreOrb emergencyStop={false} size="md" />
        <p className="text-sm font-mono text-slate-400">Initializing AI GOD (GRI v0.5)...</p>
      </div>
    );
  }

  if (!firebaseUser && !isPreviewMode) {
    return <AuthGate />;
  }

  const currentNavLabel =
    NAV_ITEMS.find((item) => item.id === activeSection)?.label || 'GOD Dashboard';

  const handleSelectNav = (section: NavSection) => {
    setActiveSection(section);
    setMobileMenuOpen(false);
  };

  const sentinelNavItems = NAV_ITEMS.filter((i) => i.group === 'sentinel');
  const griNavItems = NAV_ITEMS.filter((i) => i.group === 'gri');
  const ginNavItems = NAV_ITEMS.filter((i) => i.group === 'gin');
  const coreNavItems = NAV_ITEMS.filter((i) => i.group === 'core');

  const renderNavButton = (item: (typeof NAV_ITEMS)[number]) => {
    const Icon = item.icon;
    const isActive = activeSection === item.id;
    return (
      <button
        key={item.id}
        type="button"
        onClick={() => handleSelectNav(item.id)}
        className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
          isActive
            ? 'bg-blue-600/15 text-white border border-blue-500/30'
            : 'text-slate-400 hover:text-white hover:bg-white/[0.04] border border-transparent'
        }`}
      >
        <Icon
          className={`w-4 h-4 shrink-0 ${
            isActive
              ? 'text-blue-400'
              : item.id === 'security' && profile.emergencyStop
                ? 'text-red-400'
                : 'text-slate-500'
          }`}
        />
        <span>{item.label}</span>
      </button>
    );
  };

  return (
    <div className="min-h-screen bg-[#090b10] text-slate-100 flex">
      {/* Desktop Sidebar Navigation (260px Workspace Canvas) */}
      <aside
        aria-label="Primary command navigation"
        className="hidden lg:flex lg:w-64 shrink-0 flex-col border-r border-white/[0.08] bg-[#0b0e15] sticky top-0 h-screen"
      >
        <div className="px-5 py-4 border-b border-white/[0.07] flex items-center gap-3">
          <NeuralCoreOrb
            emergencyStop={profile.emergencyStop}
            isStreaming={isStreamingChat}
            size="sm"
          />
          <div className="min-w-0">
            <span className="block text-base font-bold tracking-tight text-white font-display truncate">
              AI GOD (GOD-X)
            </span>
            <span className="block text-[11px] font-mono text-slate-500">
              GRI v0.5 · SENTINEL v0.8
            </span>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-4">
          <div className="space-y-1">
            <p className="px-3 text-[11px] font-medium text-slate-500">
              Server Defense (SENTINEL v0.8)
            </p>
            {sentinelNavItems.map(renderNavButton)}
          </div>

          <div className="space-y-1 pt-3 border-t border-white/[0.06]">
            <p className="px-3 text-[11px] font-medium text-slate-500">
              Global Research (GRI v0.5)
            </p>
            {griNavItems.map(renderNavButton)}
          </div>

          <div className="space-y-1 pt-3 border-t border-white/[0.06]">
            <p className="px-3 text-[11px] font-medium text-slate-500">
              Network &amp; Behaviour (GIN)
            </p>
            {ginNavItems.map(renderNavButton)}
          </div>

          <div className="space-y-1 pt-3 border-t border-white/[0.06]">
            <p className="px-3 text-[11px] font-medium text-slate-500">
              GOD Core &amp; Governance
            </p>
            {coreNavItems.map(renderNavButton)}
          </div>
        </nav>

        <div className="p-4 border-t border-white/[0.07] space-y-2">
          <div className="flex items-center gap-2 text-xs text-slate-400 font-mono truncate">
            <Cpu className="w-3.5 h-3.5 text-blue-400 shrink-0" />
            <span className="truncate">Mode: {profile.executionMode}</span>
          </div>
          {!firebaseUser && (
            <button
              type="button"
              onClick={exitPreviewMode}
              className="w-full text-left text-xs text-slate-500 hover:text-slate-300 transition-colors cursor-pointer"
            >
              Return to Sign-In Gate
            </button>
          )}
        </div>
      </aside>

      {/* Mobile Slide-Over Navigation */}
      {mobileMenuOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Mobile navigation menu"
          className="fixed inset-0 z-50 lg:hidden flex"
        >
          <div
            className="fixed inset-0 bg-black/70"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="relative z-10 w-72 max-w-[85vw] bg-[#0b0e15] border-r border-white/[0.1] flex flex-col h-full">
            <div className="px-4 py-4 border-b border-white/[0.08] flex items-center justify-between">
              <span className="text-base font-bold text-white font-display">
                AI GOD · GRI v0.5
              </span>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation menu"
                className="p-1.5 text-slate-400 hover:text-white rounded-lg cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <nav className="flex-1 overflow-y-auto p-3 space-y-3">
              <div className="space-y-1">
                <p className="px-3 text-[11px] font-medium text-slate-500">
                  Server Defense (SENTINEL v0.8)
                </p>
                {sentinelNavItems.map(renderNavButton)}
              </div>
              <div className="space-y-1 pt-2 border-t border-white/[0.06]">
                <p className="px-3 text-[11px] font-medium text-slate-500">
                  Global Research (GRI v0.5)
                </p>
                {griNavItems.map(renderNavButton)}
              </div>
              <div className="space-y-1 pt-2 border-t border-white/[0.06]">
                <p className="px-3 text-[11px] font-medium text-slate-500">
                  Network &amp; Behaviour (GIN)
                </p>
                {ginNavItems.map(renderNavButton)}
              </div>
              <div className="space-y-1 pt-2 border-t border-white/[0.06]">
                <p className="px-3 text-[11px] font-medium text-slate-500">
                  GOD Core &amp; Governance
                </p>
                {coreNavItems.map(renderNavButton)}
              </div>
            </nav>
          </div>
        </div>
      )}

      {/* Main Content Viewport */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Workspace Contextual Top Bar (<= 15% mobile height) */}
        <header className="sticky top-0 z-30 h-14 px-4 sm:px-6 lg:px-8 border-b border-white/[0.08] bg-[#090b10] flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation menu"
              className="lg:hidden p-1.5 text-slate-300 hover:text-white rounded-lg shrink-0 cursor-pointer"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 text-sm min-w-0">
              <span className="hidden sm:inline text-slate-500 whitespace-nowrap">
                AI GOD GRI
              </span>
              <span aria-hidden="true" className="hidden sm:inline text-slate-600">
                /
              </span>
              <span className="font-semibold text-white truncate">{currentNavLabel}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {!firebaseUser && (
              <button
                type="button"
                onClick={signInWithGoogle}
                className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>
                  Sign in<span className="hidden sm:inline"> with Google</span>
                </span>
              </button>
            )}

            <button
              type="button"
              onClick={() => toggleEmergencyStop(!profile.emergencyStop)}
              aria-label={
                profile.emergencyStop
                  ? 'Release Emergency Stop'
                  : 'Engage Emergency Stop'
              }
              className={`inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 text-xs font-semibold rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                profile.emergencyStop
                  ? 'bg-red-600 border-red-500 text-white'
                  : 'bg-[#121722] hover:bg-red-950/40 border-red-500/30 text-red-300'
              }`}
            >
              <OctagonAlert className="w-3.5 h-3.5" />
              <span className="sm:hidden">{profile.emergencyStop ? 'Reset' : 'Stop'}</span>
              <span className="hidden sm:inline">
                {profile.emergencyStop ? 'Stop Active (Reset)' : 'Emergency Stop'}
              </span>
            </button>
          </div>
        </header>

        {/* Preview Session Notice Banner */}
        {!firebaseUser && (
          <div className="px-4 sm:px-6 lg:px-8 py-2 bg-blue-950/25 border-b border-blue-500/20 text-xs text-slate-300 flex flex-wrap items-center justify-between gap-2">
            <span>
              Preview Session (local memory). Sign in with Google to unlock live server-side Gemini
              Search Grounding, Central Brain planning, and Cloud Firestore persistence.
            </span>
          </div>
        )}

        <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 lg:py-8">
          {activeSection === 'dashboard' && <DashboardView />}
          {activeSection === 'sentinel' && <SentinelView />}
          {activeSection === 'research' && <InternetExplorerView />}
          {activeSection === 'webintel' && <WebTechIntelView />}
          {activeSection === 'serverintel' && <ServerIntelView />}
          {activeSection === 'cveintel' && <SecurityResearchView />}
          {activeSection === 'monitors' && <ContinuousResearchView />}
          {activeSection === 'network' && <NetworkObserverView />}
          {activeSection === 'behaviour' && <BehaviourEngineView />}
          {activeSection === 'knowledge' && <KnowledgeGraphView />}
          {activeSection === 'chat' && <ChatView />}
          {activeSection === 'agents' && <AgentsView />}
          {activeSection === 'vision' && <VisionModuleView />}
          {activeSection === 'voice' && <VoiceModuleView />}
          {activeSection === 'memory' && <MemoryView />}
          {activeSection === 'security' && <SecurityView />}
          {activeSection === 'automation' && <AutomationModuleView />}
          {activeSection === 'settings' && <SettingsView />}
        </main>
      </div>
    </div>
  );
};

export default function App() {
  return (
    <ErrorBoundary>
      <GodWorkspaceProvider>
        <GinIntelligenceProvider>
          <GriResearchProvider>
            <SentinelProvider>
              <CommandCenterShell />
            </SentinelProvider>
          </GriResearchProvider>
        </GinIntelligenceProvider>
      </GodWorkspaceProvider>
    </ErrorBoundary>
  );
}
