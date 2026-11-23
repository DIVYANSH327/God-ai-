import React, { useState } from 'react';
import { AlertTriangle, LogIn, LogOut, Server, Shield } from 'lucide-react';
import { useGodWorkspace } from '../context/GodWorkspaceContext';
import {
  GOD_CORE_MODEL,
  GOD_CORE_VERSION,
  PROVIDER_DESCRIPTORS,
} from '../shared/godCoreLogic';
import type { ExecutionMode } from '../shared/types';

export const SettingsView: React.FC = () => {
  const {
    firebaseUser,
    profile,
    privateEmail,
    systemInfo,
    signInWithGoogle,
    signOutUser,
    setExecutionMode,
  } = useGodWorkspace();

  const [selectedOsTab, setSelectedOsTab] = useState<'windows' | 'kali'>('windows');
  const [topologyImgFailed, setTopologyImgFailed] = useState(false);

  const modes: Array<{
    id: ExecutionMode;
    title: string;
    subtitle: string;
    statusNote: string;
  }> = [
    {
      id: 'cloud',
      title: 'Cloud Mode (Recommended v0.1)',
      subtitle: `Routes all GOD Core reasoning through server-side Google Gemini (${GOD_CORE_MODEL}).`,
      statusNote: 'Operational now',
    },
    {
      id: 'hybrid',
      title: 'Hybrid Cloud + Local Mode',
      subtitle:
        'Prefers Gemini Cloud for orchestration and falls back cleanly while 0 local nodes are paired.',
      statusNote: 'Cloud active · Local bridge unpaired (0 nodes)',
    },
    {
      id: 'local',
      title: 'Strict Local Node Mode',
      subtitle:
        'Restricts inference exclusively to enrolled local hardware (Ollama / vLLM). Withholds cloud calls.',
      statusNote: 'Disabled until a local node is paired',
    },
  ];

  return (
    <div className="space-y-8">
      <div className="space-y-1">
        <h1 className="text-2xl font-bold text-white">Settings & Hybrid Node Architecture</h1>
        <p className="text-sm text-slate-400 max-w-2xl">
          Manage your authenticated operator profile, server-side Gemini model configuration,
          inference routing mode, and outbound Windows / Kali Linux node enrollment specification.
        </p>
      </div>

      {/* Profile & Model Info Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <section className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5">
          <div className="flex items-center justify-between gap-4">
            <h2 className="text-lg font-semibold text-white">Operator Profile</h2>
            {firebaseUser ? (
              <button
                type="button"
                onClick={signOutUser}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-white/[0.07] hover:bg-white/[0.12] text-slate-100 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={signInWithGoogle}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Sign in with Google</span>
              </button>
            )}
          </div>

          <dl className="divide-y divide-white/[0.06] border-t border-white/[0.06] text-sm">
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Display Name</dt>
              <dd className="font-medium text-white truncate">{profile.displayName}</dd>
            </div>
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Isolated Account Email</dt>
              <dd className="font-mono text-xs text-slate-200 truncate">{privateEmail}</dd>
            </div>
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Tenant UID</dt>
              <dd className="font-mono text-xs text-slate-400 truncate">{profile.uid}</dd>
            </div>
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Persistence Isolation</dt>
              <dd className="text-xs font-mono text-blue-400">
                {firebaseUser ? 'Cloud Firestore (/users/{uid})' : 'Preview Session'}
              </dd>
            </div>
          </dl>
        </section>

        <section className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5">
          <div className="flex items-center gap-2 text-blue-400">
            <Server className="w-4 h-4 shrink-0" />
            <h2 className="text-lg font-semibold text-white">Model & Provider Registry</h2>
          </div>

          <dl className="divide-y divide-white/[0.06] border-t border-white/[0.06] text-sm">
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Platform Version</dt>
              <dd className="font-mono text-xs text-white tabular-nums">
                GOD-X v{systemInfo?.version || GOD_CORE_VERSION}
              </dd>
            </div>
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Primary Cloud Model</dt>
              <dd className="font-mono text-xs text-blue-400">
                {systemInfo?.coreModel || GOD_CORE_MODEL}
              </dd>
            </div>
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">API Key Boundary</dt>
              <dd className="font-mono text-xs text-emerald-400">
                Server-Only (@google/genai SDK)
              </dd>
            </div>
            <div className="py-3 flex items-center justify-between gap-4">
              <dt className="text-slate-400">Enrolled Local Nodes</dt>
              <dd className="font-mono text-xs text-slate-300 tabular-nums">
                {systemInfo?.pairedLocalNodes ?? 0} paired
              </dd>
            </div>
          </dl>

          <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
            {PROVIDER_DESCRIPTORS.map((prov) => (
              <div key={prov.id} className="py-3 text-xs space-y-1">
                <div className="flex items-center justify-between font-mono">
                  <span className="text-slate-200 font-semibold">{prov.name}</span>
                  <span
                    className={
                      prov.status === 'active' ? 'text-emerald-400' : 'text-slate-500'
                    }
                  >
                    {prov.status === 'active' ? 'Active' : 'Unpaired · Disabled'}
                  </span>
                </div>
                <p className="text-slate-400 leading-relaxed">{prov.summary}</p>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Cloud / Hybrid / Local Execution Mode Selector (Single Elevation) */}
      <section className="space-y-4 pt-2 border-t border-white/[0.08]">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold text-white">Inference Execution Mode</h2>
          <p className="text-xs text-slate-400">
            Select how GOD Core routes intelligence requests. Local execution remains disabled until
            a workstation node is cryptographically enrolled.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {modes.map((m) => {
            const active = profile.executionMode === m.id;
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => setExecutionMode(m.id)}
                className={`text-left p-5 rounded-xl border transition-colors flex flex-col justify-between space-y-4 cursor-pointer ${
                  active
                    ? 'bg-blue-950/25 border-blue-500 text-white'
                    : 'bg-[#0f131c] border-white/[0.08] text-slate-300 hover:border-white/[0.18]'
                }`}
              >
                <div className="space-y-1.5">
                  <p className="text-sm font-semibold text-white">{m.title}</p>
                  <p className="text-xs text-slate-400 leading-relaxed">{m.subtitle}</p>
                </div>
                <p className="text-xs font-mono text-blue-300">{m.statusNote}</p>
              </button>
            );
          })}
        </div>

        {profile.executionMode !== 'cloud' && (
          <div
            role="status"
            className="p-4 rounded-xl bg-[#0f131c] border border-amber-500/35 flex items-start gap-3 text-xs text-amber-200"
          >
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              {profile.executionMode === 'local'
                ? 'Strict Local Mode is saved as your preference, but 0 local nodes are paired. Chat requests will be withheld rather than silently sent to the cloud until you enroll a node or switch back to Cloud / Hybrid mode.'
                : 'Hybrid Mode is configured. Because 0 local nodes are paired in v0.1, GOD Core executes via Gemini Cloud and transparently tags responses.'}
            </p>
          </div>
        )}
      </section>

      {/* Secure Local-Node Enrollment Architecture (Windows & Kali Linux) */}
      <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
          <div className="lg:col-span-7 space-y-4">
            <div className="flex items-center gap-2 text-blue-400">
              <Shield className="w-4 h-4 shrink-0" />
              <h2 className="text-lg font-semibold text-white">
                Local-Node Enrollment Architecture (v0.2 Spec)
              </h2>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed">
              A cloud-hosted web application cannot—and must never attempt to—connect directly to{' '}
              <code className="px-1.5 py-0.5 rounded bg-white/[0.07] font-mono text-xs">
                http://localhost:11434
              </code>{' '}
              or private LAN addresses. Instead, AI GOD defines an outbound-only zero-trust bridge
              for Windows and Kali Linux workstations:
            </p>

            <ol className="space-y-2 text-xs text-slate-300 leading-relaxed list-decimal pl-4">
              <li>
                <strong className="text-white">Short-Lived Enrollment Token:</strong> Operator
                generates a single-use 5-minute token bound to their Firebase UID.
              </li>
              <li>
                <strong className="text-white">Outbound TLS 1.3 / WSS Relay:</strong> The local node
                daemon initiates an outbound encrypted WebSocket connection—opening zero inbound
                firewall ports.
              </li>
              <li>
                <strong className="text-white">Ed25519 Device Keypair & Least Privilege:</strong>{' '}
                Each node runs as an unprivileged service restricted to local Ollama inference or
                explicitly approved read-only tasks, severable instantly via Emergency Stop.
              </li>
            </ol>

            <div className="pt-2 space-y-3">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedOsTab('windows')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg border whitespace-nowrap shrink-0 cursor-pointer ${
                    selectedOsTab === 'windows'
                      ? 'bg-blue-600 border-blue-500 text-white'
                      : 'bg-[#090b10] border-white/[0.08] text-slate-400 hover:text-white'
                  }`}
                >
                  Windows 11 Node Spec
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedOsTab('kali')}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg border whitespace-nowrap shrink-0 cursor-pointer ${
                    selectedOsTab === 'kali'
                      ? 'bg-blue-600 border-blue-500 text-white'
                      : 'bg-[#090b10] border-white/[0.08] text-slate-400 hover:text-white'
                  }`}
                >
                  Kali Linux Node Spec
                </button>
              </div>

              <div className="p-4 rounded-lg bg-[#090b10] border border-white/[0.08] font-mono text-xs text-slate-300 space-y-1.5">
                {selectedOsTab === 'windows' ? (
                  <>
                    <p className="text-slate-400">
                      Target: Windows Service (DPAPI Keychain + Ollama 127.0.0.1 Loopback Proxy)
                    </p>
                    <p className="text-blue-300">
                      Status: Staged v0.2 · Pairing Endpoint Inactive in v0.1 (0 nodes enrolled)
                    </p>
                  </>
                ) : (
                  <>
                    <p className="text-slate-400">
                      Target: Kali Linux systemd DynamicUser=yes (AppArmor confined · No root/raw sockets)
                    </p>
                    <p className="text-blue-300">
                      Status: Staged v0.2 · Defensive Telemetry Only · Pairing Inactive in v0.1
                    </p>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="lg:col-span-5 relative rounded-xl border border-white/[0.08] bg-[#090b10] overflow-hidden min-h-[240px] flex items-end p-5">
            {!topologyImgFailed && (
              <img
                src="/src/assets/images/hybrid_node_architecture_1795262187243.jpg"
                alt="Isometric outbound cloud-to-workstation optical conduit topology"
                referrerPolicy="no-referrer"
                onError={() => setTopologyImgFailed(true)}
                className="absolute inset-0 w-full h-full object-cover opacity-80"
              />
            )}
            <div className="absolute inset-0 bg-gradient-to-t from-[#090b10] via-[#090b10]/40 to-transparent" />
            <div className="relative z-10 space-y-0.5">
              <p className="text-xs font-semibold text-white">
                Outbound WSS + mTLS Bridge Topology
              </p>
              <p className="text-[11px] font-mono text-slate-400">
                Zero Inbound Ports · Explicit UID Attestation
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};
