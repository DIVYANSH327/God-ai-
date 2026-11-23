import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Check, Copy } from 'lucide-react';
import { isSafeExternalUrl } from '../shared/validation';

interface CodeBlockProps {
  language: string;
  code: string;
}

const FencedCodeBlock: React.FC<CodeBlockProps> = ({ language, code }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard unavailable
    }
  };

  return (
    <div className="my-3 rounded-lg border border-white/[0.09] bg-[#090b10] overflow-hidden">
      <div className="flex items-center justify-between px-3.5 py-1.5 border-b border-white/[0.07] bg-[#0e121b] text-xs text-slate-400">
        <span className="font-mono">{language || 'code'}</span>
        <button
          type="button"
          onClick={handleCopy}
          aria-label="Copy code block"
          className="inline-flex items-center gap-1.5 text-xs text-slate-300 hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3.5 overflow-x-auto text-[13px] leading-relaxed font-mono text-slate-200">
        <code>{code}</code>
      </pre>
    </div>
  );
};

export const MarkdownRenderer: React.FC<{ content: string }> = ({ content }) => {
  return (
    <div className="space-y-3 text-[15px] leading-relaxed text-slate-200 break-words">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="text-xl font-semibold text-white mt-4 mb-2">{children}</h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-lg font-semibold text-white mt-4 mb-2">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-base font-semibold text-slate-100 mt-3 mb-1.5">{children}</h3>
          ),
          p: ({ children }) => <p className="text-slate-200 leading-relaxed">{children}</p>,
          ul: ({ children }) => (
            <ul className="list-disc pl-5 space-y-1.5 text-slate-200">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal pl-5 space-y-1.5 text-slate-200">{children}</ol>
          ),
          li: ({ children }) => <li className="leading-relaxed">{children}</li>,
          blockquote: ({ children }) => (
            <blockquote className="pl-4 py-1 text-slate-300 italic bg-white/[0.03] rounded-md border border-white/[0.07]">
              {children}
            </blockquote>
          ),
          a: ({ href, children }) => {
            if (!isSafeExternalUrl(href)) {
              return <span className="text-slate-300 underline">{children}</span>;
            }
            return (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 hover:text-blue-300 underline underline-offset-2"
              >
                {children}
              </a>
            );
          },
          table: ({ children }) => (
            <div className="overflow-x-auto my-3 border border-white/[0.08] rounded-lg">
              <table className="w-full text-left text-sm border-collapse">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="px-3 py-2 bg-[#121722] border-b border-white/[0.08] font-semibold text-slate-200 text-xs">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="px-3 py-2 border-b border-white/[0.05] text-slate-300 text-xs tabular-nums">
              {children}
            </td>
          ),
          code: ({ className, children }) => {
            const rawText = String(children).replace(/\n$/, '');
            const match = /language-([\w-]+)/.exec(className || '');
            const isBlock = Boolean(match) || rawText.includes('\n');
            if (isBlock) {
              return <FencedCodeBlock language={match?.[1] || 'text'} code={rawText} />;
            }
            return (
              <code className="px-1.5 py-0.5 rounded bg-white/[0.08] font-mono text-[13px] text-blue-200">
                {children}
              </code>
            );
          },
          pre: ({ children }) => <>{children}</>,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};
