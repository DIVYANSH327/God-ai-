import React, { useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  Check,
  Copy,
  Loader2,
  LogIn,
  MessageSquarePlus,
  Send,
  Square,
  Trash2,
} from 'lucide-react';
import { useGodWorkspace } from '../context/GodWorkspaceContext';
import { MarkdownRenderer } from '../components/MarkdownRenderer';
import { GOD_CORE_MODEL } from '../shared/godCoreLogic';

export const ChatView: React.FC = () => {
  const {
    firebaseUser,
    signInWithGoogle,
    profile,
    conversations,
    activeConversationId,
    selectConversation,
    startNewConversation,
    prefillChatInput,
    clearPrefillChatInput,
    messages,
    deleteConversation,
    isStreamingChat,
    streamingText,
    streamingMeta,
    chatError,
    clearChatError,
    sendChatMessage,
    abortActiveStream,
  } = useGodWorkspace();

  const [input, setInput] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (prefillChatInput) {
      setInput(prefillChatInput);
      clearPrefillChatInput();
    }
  }, [prefillChatInput, clearPrefillChatInput]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length, streamingText]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isStreamingChat) return;
    const currentPrompt = input;
    if (!currentPrompt.trim()) {
      await sendChatMessage('');
      return;
    }
    if (firebaseUser && !profile.emergencyStop && profile.executionMode !== 'local') {
      setInput('');
    }
    await sendChatMessage(currentPrompt);
  };

  const handleCopyMessage = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      window.setTimeout(() => setCopiedId(null), 1800);
    } catch {
      // Clipboard blocked
    }
  };

  const starterPrompts = [
    'Design a secure hybrid cloud-to-local WebSocket relay protocol for AI agents.',
    'Write a TypeScript token-bucket rate limiter with unit test assertions.',
    'Compare Firestore split-collection PII isolation vs field-level encryption.',
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-[calc(100vh-11rem)]">
      {/* Thread History Sidebar */}
      <aside
        aria-label="Conversation history"
        className="lg:col-span-3 rounded-xl bg-[#0f131c] border border-white/[0.08] p-4 flex flex-col max-h-[320px] lg:max-h-[calc(100vh-11rem)]"
      >
        <div className="flex items-center justify-between gap-2 pb-3 border-b border-white/[0.07]">
          <h2 className="text-sm font-semibold text-white">Conversations</h2>
          <button
            type="button"
            onClick={() => startNewConversation()}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <MessageSquarePlus className="w-3.5 h-3.5" />
            <span>New</span>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto py-2 space-y-1">
          {conversations.length === 0 ? (
            <p className="text-xs text-slate-500 py-6 text-center px-2">
              No saved threads yet. Send a message to create your first thread.
            </p>
          ) : (
            conversations.map((conv) => {
              const isSelected = conv.id === activeConversationId;
              return (
                <div
                  key={conv.id}
                  className={`group flex items-center justify-between gap-2 rounded-lg px-3 py-2.5 transition-colors ${
                    isSelected
                      ? 'bg-blue-600/15 text-white border border-blue-500/30'
                      : 'text-slate-300 hover:bg-white/[0.04] border border-transparent'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => selectConversation(conv.id)}
                    className="flex-1 min-w-0 text-left space-y-0.5 cursor-pointer"
                  >
                    <p className="text-xs font-medium truncate">{conv.title}</p>
                    <p className="text-[11px] font-mono text-slate-500 tabular-nums truncate">
                      {conv.lastIntent} · {conv.messageCount} msgs
                    </p>
                  </button>
                  <button
                    type="button"
                    onClick={() => deleteConversation(conv.id)}
                    aria-label={`Delete conversation "${conv.title}"`}
                    className="p-1 text-slate-500 hover:text-red-400 transition-colors shrink-0 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })
          )}
        </div>
      </aside>

      {/* Main Conversational Panel */}
      <section className="lg:col-span-9 rounded-xl bg-[#0f131c] border border-white/[0.08] flex flex-col max-h-[calc(100vh-11rem)] min-h-[520px]">
        {/* Chat Context Header */}
        <div className="px-5 py-3.5 border-b border-white/[0.07] flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-base font-semibold text-white truncate">
              {activeConversationId
                ? conversations.find((c) => c.id === activeConversationId)?.title || 'Active Thread'
                : 'New GOD Core Session'}
            </h1>
            <p className="text-xs font-mono text-slate-400 tabular-nums">
              Engine: {GOD_CORE_MODEL} · Mode: {profile.executionMode} ·{' '}
              {firebaseUser ? 'Firestore Encrypted Sync' : 'Preview Read-Only Auth Gate'}
            </p>
          </div>

          {!firebaseUser && (
            <button
              type="button"
              onClick={() => signInWithGoogle()}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Sign in for Live Gemini</span>
            </button>
          )}
        </div>

        {/* Message Stream Area */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {messages.length === 0 && !isStreamingChat ? (
            <div className="h-full flex flex-col items-center justify-center text-center max-w-xl mx-auto py-10 space-y-6">
              <div className="space-y-2">
                <h2 className="text-xl font-semibold text-white">GOD Core Intelligence Ready</h2>
                <p className="text-sm text-slate-400 leading-relaxed">
                  Every prompt is classified across Chat, Research, Coding, Vision, Security, and
                  Automation. Conversational reasoning runs server-side via Gemini while keeping
                  unimplemented v0.2 specialist modules clearly labeled.
                </p>
              </div>

              <div className="w-full space-y-2 text-left">
                <p className="text-xs font-mono text-slate-500">Suggested prompts</p>
                {starterPrompts.map((sample) => (
                  <button
                    key={sample}
                    type="button"
                    onClick={() => setInput(sample)}
                    className="w-full text-left p-3 rounded-lg bg-[#090b10] hover:bg-[#141a26] border border-white/[0.08] text-xs text-slate-200 transition-colors cursor-pointer"
                  >
                    {sample}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((msg) => (
              <article
                key={msg.id}
                className={`space-y-2 ${
                  msg.role === 'user' ? 'ml-auto max-w-2xl' : 'mr-auto max-w-3xl w-full'
                }`}
              >
                <div className="flex items-center justify-between gap-3 text-xs font-mono text-slate-400 tabular-nums">
                  <span>
                    {msg.role === 'user' ? 'Operator' : 'GOD Core'} · {msg.intent}
                  </span>
                  {msg.role === 'assistant' && (
                    <button
                      type="button"
                      onClick={() => handleCopyMessage(msg.id, msg.content)}
                      aria-label="Copy response"
                      className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      {copiedId === msg.id ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy response</span>
                        </>
                      )}
                    </button>
                  )}
                </div>

                <div
                  className={`rounded-xl p-4 border ${
                    msg.role === 'user'
                      ? 'bg-blue-950/25 border-blue-500/25 text-slate-100'
                      : 'bg-[#090b10] border-white/[0.08] text-slate-200'
                  }`}
                >
                  {msg.role === 'user' ? (
                    <p className="text-[15px] leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                  ) : (
                    <MarkdownRenderer content={msg.content} />
                  )}
                </div>

                {msg.role === 'assistant' && msg.agentModuleNote && (
                  <p className="text-[11px] font-mono text-slate-500 leading-normal">
                    {msg.agentModuleNote}
                  </p>
                )}
              </article>
            ))
          )}

          {/* Live Streaming Assistant Turn */}
          {isStreamingChat && (
            <article className="mr-auto max-w-3xl w-full space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono text-blue-400">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>
                  Streaming GOD Core{streamingMeta ? ` · ${streamingMeta.intent}` : ''}
                </span>
              </div>
              <div className="rounded-xl p-4 bg-[#090b10] border border-blue-500/30">
                {streamingText ? (
                  <MarkdownRenderer content={streamingText} />
                ) : (
                  <p className="text-sm text-slate-400">Synthesizing response...</p>
                )}
              </div>
              {streamingMeta?.agentModuleNote && (
                <p className="text-[11px] font-mono text-slate-500">
                  {streamingMeta.agentModuleNote}
                </p>
              )}
            </article>
          )}

          {chatError && (
            <div
              role="alert"
              className="rounded-lg p-3.5 bg-red-950/30 border border-red-500/35 flex items-start justify-between gap-3 text-sm text-red-200"
            >
              <div className="flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <p className="leading-relaxed">{chatError}</p>
              </div>
              <button
                type="button"
                onClick={clearChatError}
                className="text-xs text-red-300 hover:text-white whitespace-nowrap shrink-0 cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Prompt Composer */}
        <form
          onSubmit={handleSubmit}
          className="p-4 border-t border-white/[0.08] bg-[#0b0e15] rounded-b-xl space-y-2"
        >
          <div className="flex items-end gap-3">
            <label htmlFor="god-chat-input" className="sr-only">
              Message GOD Core
            </label>
            <textarea
              id="god-chat-input"
              rows={2}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  void handleSubmit(e);
                }
              }}
              placeholder={
                profile.emergencyStop
                  ? 'Emergency Stop is engaged — disengage in Security Center to chat...'
                  : 'Ask GOD Core to reason, write code, synthesize research, or review security...'
              }
              className="flex-1 resize-none px-3.5 py-2.5 text-sm bg-[#090b10] border border-white/[0.1] rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />

            {isStreamingChat ? (
              <button
                type="button"
                onClick={abortActiveStream}
                className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Square className="w-3.5 h-3.5" />
                <span>Stop</span>
              </button>
            ) : (
              <button
                type="submit"
                className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Send</span>
              </button>
            )}
          </div>
        </form>
      </section>
    </div>
  );
};
