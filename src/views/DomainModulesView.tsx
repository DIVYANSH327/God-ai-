import React, { useState } from 'react';
import { ArrowRight, Clock, FlaskConical, Plus, ShieldCheck } from 'lucide-react';
import { useGodWorkspace } from '../context/GodWorkspaceContext';
import type { TaskPriority } from '../shared/types';

export const ResearchModuleView: React.FC = () => {
  const { profile, startNewConversation, setActiveSection } = useGodWorkspace();
  const [topic, setTopic] = useState('');
  const [scope, setScope] = useState<'architecture' | 'literature' | 'risk'>('architecture');

  const handleLaunchResearch = (e: React.FormEvent) => {
    e.preventDefault();
    const subject =
      topic.trim() ||
      'Zero-trust local node attestation protocols for hybrid personal AI platforms';
    const framing =
      scope === 'architecture'
        ? 'Research and compare system architectures, trade-offs, and failure modes for:'
        : scope === 'literature'
          ? 'Synthesize key foundational concepts, methodologies, and open questions for:'
          : 'Conduct a defensive risk and threat-surface analysis for:';
    startNewConversation(`${framing} ${subject}`);
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-amber-300">
          <FlaskConical className="w-3.5 h-3.5" />
          <span>Prototype Module (v0.1 Reasoning via Gemini Cloud · Web Crawler Planned v0.2)</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Research Synthesis</h1>
        <p className="text-sm text-slate-400 max-w-2xl">
          Frame structured research inquiries for GOD Core. Live external web crawling is not
          executed in v0.1; Gemini synthesizes structured analysis transparently.
        </p>
      </div>

      <form
        onSubmit={handleLaunchResearch}
        className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-5 max-w-3xl"
      >
        <div className="space-y-2">
          <label htmlFor="research-topic-input" className="block text-sm font-medium text-slate-200">
            Research Question or Technical Domain
          </label>
          <textarea
            id="research-topic-input"
            rows={3}
            value={topic}
            onChange={(e) => setTopic(e.target.value)}
            placeholder="e.g., Compare WebSocket mTLS vs WireGuard userspace tunnels for enrolling remote developer workstations..."
            className="w-full px-3.5 py-2.5 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="space-y-2">
          <span className="block text-xs font-medium text-slate-300">Analytical Lens</span>
          <div className="flex flex-wrap items-center gap-2">
            {(
              [
                { id: 'architecture', label: 'Architecture & Trade-offs' },
                { id: 'literature', label: 'Concept & Literature Synthesis' },
                { id: 'risk', label: 'Threat & Risk Matrix' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                onClick={() => setScope(opt.id)}
                className={`px-3.5 py-1.5 text-xs font-medium rounded-lg border transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  scope === opt.id
                    ? 'bg-blue-600 border-blue-500 text-white'
                    : 'bg-[#090b10] border-white/[0.08] text-slate-300 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        <div className="pt-3 border-t border-white/[0.07] flex flex-wrap items-center justify-between gap-4">
          <p className="text-xs font-mono text-slate-400">
            Web Research Approval Gate:{' '}
            <button
              type="button"
              onClick={() => setActiveSection('security')}
              className="text-blue-400 hover:underline cursor-pointer"
            >
              {profile.allowWebResearch ? 'Approved (Staged for v0.2)' : 'Locked in Security Center'}
            </button>
          </p>

          <button
            type="submit"
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <span>Send to GOD Core Chat</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>
    </div>
  );
};

export const VisionModuleView: React.FC = () => {
  const { profile, setActiveSection, startNewConversation } = useGodWorkspace();

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5" />
          <span>Planned Capability (v0.2 Roadmap — Not Executed in v0.1)</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Vision & Diagram Analysis</h1>
        <p className="text-sm text-slate-400 max-w-2xl">
          Staged multimodal pipeline for inspecting architecture diagrams, UI screenshots, and
          technical schematics. Direct binary image ingestion is intentionally disabled in v0.1 so no
          unimplemented agent claims visual execution.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-4xl">
        <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-3">
          <h2 className="text-base font-semibold text-white">v0.2 Ingestion Pipeline Spec</h2>
          <ul className="space-y-2 text-sm text-slate-300 leading-relaxed">
            <li>· Client MIME validation (PNG, JPEG, WebP up to 4 MB; zero raw Firestore blob storage)</li>
            <li>· Server-side inlineData multimodal forwarding to Gemini Vision</li>
            <li>· Explicit per-session File Analysis consent gate in Security Center</li>
          </ul>
          <p className="pt-2 text-xs font-mono text-slate-400">
            Current File Analysis Gate: {profile.allowFileAnalysis ? 'Approved' : 'Locked'}
          </p>
        </div>

        <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <h2 className="text-base font-semibold text-white">Text-Based Architecture Review</h2>
            <p className="text-sm text-slate-400 leading-relaxed">
              Need diagram feedback right now? Paste Mermaid, ASCII, or component descriptions into
              AI Chat for immediate structural analysis via GOD Core.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() =>
                startNewConversation(
                  'Generate a clean Mermaid sequence diagram for zero-trust client-to-server Gemini streaming with Firebase ID token verification.'
                )
              }
              className="px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              Draft Architecture Diagram in Chat
            </button>
            <button
              type="button"
              onClick={() => setActiveSection('security')}
              className="px-4 py-2 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              Permissions
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export const VoiceModuleView: React.FC = () => {
  const { setActiveSection } = useGodWorkspace();

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5" />
          <span>Planned Capability (v0.2 Roadmap — Microphone Unrequested in v0.1)</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Neural Voice Link</h1>
        <p className="text-sm text-slate-400 max-w-2xl">
          Staged bidirectional speech interface targeting Gemini Live native audio. In v0.1, AI GOD
          requests zero browser microphone permissions and keeps audio streaming offline.
        </p>
      </div>

      <div className="rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 max-w-3xl space-y-4">
        <div className="flex items-center gap-2 text-slate-200">
          <ShieldCheck className="w-4 h-4 text-blue-400" />
          <h2 className="text-base font-semibold">Hardware Privacy & Stream Spec (v0.2)</h2>
        </div>
        <ul className="space-y-2 text-sm text-slate-300 leading-relaxed">
          <li>· Ephemeral server-bridged WebSocket session to gemini-3.8-live (16 kHz PCM input / 24 kHz output)</li>
          <li>· Strictly push-to-talk activation—zero passive wake-word listening</li>
          <li>· Immediate hardware track teardown when Emergency Stop is triggered</li>
        </ul>
        <div className="pt-2">
          <button
            type="button"
            onClick={() => setActiveSection('agents')}
            className="px-4 py-2 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.1] text-slate-200 rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
          >
            View VOX-06 Agent Card
          </button>
        </div>
      </div>
    </div>
  );
};

export const AutomationModuleView: React.FC = () => {
  const { profile, tasks, createTask, setActiveSection } = useGodWorkspace();
  const [workflowTitle, setWorkflowTitle] = useState('');
  const [priority, setPriority] = useState<TaskPriority>('medium');
  const [feedback, setFeedback] = useState<string | null>(null);

  const automationTasks = tasks.filter((t) => t.category === 'automation');

  const handleStageAutomation = async (e: React.FormEvent) => {
    e.preventDefault();
    setFeedback(null);
    const res = await createTask({
      title: workflowTitle,
      category: 'automation',
      priority,
    });
    if (!res.ok) {
      setFeedback(res.error || 'Enter a workflow task title.');
    } else {
      setWorkflowTitle('');
      setFeedback(
        'Staged in your manual Task Queue. Autonomous background cron execution is Planned (v0.2).'
      );
    }
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5" />
          <span>Planned Autonomous Runner (v0.2) · Manual Task Staging Active (v0.1)</span>
        </div>
        <h1 className="text-2xl font-bold text-white">Automation & Workflows</h1>
        <p className="text-sm text-slate-400 max-w-2xl">
          Background cron triggers and unattended agent dispatches are disabled in v0.1. Stage
          human-reviewed automation blueprints into your persistent task queue below.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <form
          onSubmit={handleStageAutomation}
          className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4"
        >
          <h2 className="text-base font-semibold text-white">Stage Automation Blueprint</h2>
          <div className="space-y-2">
            <label htmlFor="automation-title" className="block text-xs font-medium text-slate-300">
              Workflow Description
            </label>
            <input
              id="automation-title"
              type="text"
              value={workflowTitle}
              onChange={(e) => setWorkflowTitle(e.target.value)}
              placeholder="e.g., Weekly Firestore security audit summary..."
              maxLength={200}
              className="w-full px-3.5 py-2 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-center justify-between gap-3">
            <select
              aria-label="Workflow priority"
              value={priority}
              onChange={(e) => setPriority(e.target.value as TaskPriority)}
              className="px-3 py-2 text-xs bg-[#090b10] border border-white/[0.1] rounded-lg text-slate-200"
            >
              <option value="high">High Priority</option>
              <option value="medium">Medium Priority</option>
              <option value="low">Low Priority</option>
            </select>

            <button
              type="submit"
              className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              <span>Stage Task</span>
            </button>
          </div>

          {feedback && <p className="text-xs text-blue-300">{feedback}</p>}

          <p className="text-xs font-mono text-slate-500 pt-2 border-t border-white/[0.06]">
            Automation Queue Gate:{' '}
            <button
              type="button"
              onClick={() => setActiveSection('security')}
              className="text-blue-400 hover:underline cursor-pointer"
            >
              {profile.allowAutomationQueue ? 'Approved (Staged)' : 'Locked'}
            </button>
          </p>
        </form>

        <div className="lg:col-span-6 rounded-xl bg-[#0f131c] border border-white/[0.08] p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">Staged Automation Items</h2>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {automationTasks.length} items
            </span>
          </div>

          {automationTasks.length === 0 ? (
            <p className="text-sm text-slate-400 py-6 text-center border-t border-white/[0.06]">
              No automation tasks staged yet.
            </p>
          ) : (
            <div className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
              {automationTasks.map((item) => (
                <div key={item.id} className="py-3 space-y-0.5">
                  <p className="text-sm font-medium text-slate-100">{item.title}</p>
                  <p className="text-xs font-mono text-slate-400 tabular-nums">
                    {item.priority} priority · {item.status.replace('_', ' ')}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
