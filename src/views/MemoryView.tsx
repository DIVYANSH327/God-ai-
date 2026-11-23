import React, { useState } from 'react';
import { ExternalLink, Search, Trash2 } from 'lucide-react';
import { useGodWorkspace } from '../context/GodWorkspaceContext';

export const MemoryView: React.FC = () => {
  const {
    firebaseUser,
    conversations,
    tasks,
    selectConversation,
    setActiveSection,
    deleteConversation,
    deleteTask,
  } = useGodWorkspace();

  const [tab, setTab] = useState<'all' | 'conversations' | 'tasks'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const q = searchQuery.trim().toLowerCase();

  const filteredConvs = conversations.filter(
    (c) =>
      !q ||
      c.title.toLowerCase().includes(q) ||
      c.lastIntent.toLowerCase().includes(q) ||
      c.lastMessagePreview.toLowerCase().includes(q)
  );

  const filteredTasks = tasks.filter(
    (t) =>
      !q ||
      t.title.toLowerCase().includes(q) ||
      t.category.toLowerCase().includes(q) ||
      t.status.toLowerCase().includes(q)
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold text-white">Memory Vault</h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            {firebaseUser
              ? 'Persistent records isolated exclusively to your authenticated Firebase UID in Cloud Firestore.'
              : 'Viewing local preview records. Sign in with Google to persist and manage Cloud Firestore memory.'}
          </p>
        </div>

        <div
          role="group"
          aria-label="Filter memory record types"
          className="flex items-center gap-1 p-1 bg-[#0f131c] border border-white/[0.08] rounded-lg self-start"
        >
          {(
            [
              { id: 'all', label: `All (${conversations.length + tasks.length})` },
              { id: 'conversations', label: `Threads (${conversations.length})` },
              { id: 'tasks', label: `Tasks (${tasks.length})` },
            ] as const
          ).map((item) => (
            <button
              key={item.id}
              type="button"
              onClick={() => setTab(item.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                tab === item.id ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative max-w-md">
        <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
        <label htmlFor="memory-search-input" className="sr-only">
          Search saved memory records
        </label>
        <input
          id="memory-search-input"
          type="search"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter conversations or tasks..."
          className="w-full pl-9 pr-3.5 py-2 text-sm bg-[#0f131c] border border-white/[0.09] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* Saved Conversations Table */}
      {(tab === 'all' || tab === 'conversations') && (
        <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] overflow-hidden">
          <div className="px-5 py-4 border-b border-white/[0.07] flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">Saved Conversation Threads</h2>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {filteredConvs.length} records
            </span>
          </div>

          {filteredConvs.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-400">
              No matching conversation records in memory.
            </div>
          ) : (
            <div className="divide-y divide-white/[0.06]">
              {filteredConvs.map((conv) => (
                <div
                  key={conv.id}
                  className="px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors"
                >
                  <div className="min-w-0 space-y-1">
                    <p className="text-sm font-medium text-white truncate">{conv.title}</p>
                    <p className="text-xs text-slate-400 truncate">
                      {conv.lastMessagePreview || 'Empty thread'}
                    </p>
                    <p className="text-xs font-mono text-slate-500 tabular-nums">
                      Intent: {conv.lastIntent} · {conv.messageCount} messages · Updated{' '}
                      {new Date(conv.updatedAtMs).toLocaleDateString()}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => {
                        selectConversation(conv.id);
                        setActiveSection('chat');
                      }}
                      aria-label={`Open conversation "${conv.title}"`}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-white/[0.06] hover:bg-white/[0.12] text-slate-200 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <span>Open</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </button>

                    <button
                      type="button"
                      onClick={() => deleteConversation(conv.id)}
                      aria-label={`Delete saved conversation "${conv.title}"`}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-red-950/35 hover:bg-red-900/50 text-red-300 border border-red-500/25 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Saved Tasks Table */}
      {(tab === 'all' || tab === 'tasks') && (
        <section className="rounded-xl bg-[#0f131c] border border-white/[0.08] overflow-hidden">
          <div className="px-5 py-4 border-b border-white/[0.07] flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">Saved Task Records</h2>
            <span className="text-xs font-mono text-slate-400 tabular-nums">
              {filteredTasks.length} records
            </span>
          </div>

          {filteredTasks.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-400">
              No matching task records in memory.
            </div>
          ) : (
            <div className="divide-y divide-white/[0.06]">
              {filteredTasks.map((task) => (
                <div
                  key={task.id}
                  className="px-5 py-3.5 flex items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors"
                >
                  <div className="min-w-0 space-y-0.5">
                    <p className="text-sm font-medium text-white truncate">{task.title}</p>
                    <p className="text-xs font-mono text-slate-500 tabular-nums">
                      {task.category} · {task.priority} priority · {task.status.replace('_', ' ')}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => deleteTask(task.id)}
                    aria-label={`Delete saved task "${task.title}"`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-red-950/35 hover:bg-red-900/50 text-red-300 border border-red-500/25 rounded-md whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete</span>
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
};
