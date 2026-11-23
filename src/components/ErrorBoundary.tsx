import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface ErrorBoundaryState {
  hasError: boolean;
  errorMessage: string;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    const raw = error instanceof Error ? error.message : String(error);
    return { hasError: true, errorMessage: raw };
  }

  componentDidCatch(error: unknown, info: React.ErrorInfo): void {
    console.error('AI GOD Application ErrorBoundary:', error, info.componentStack);
  }

  private handleReset = (): void => {
    this.setState({ hasError: false, errorMessage: '' });
  };

  render(): React.ReactNode {
    if (!this.state.hasError) {
      return this.props.children;
    }

    let parsedSummary = this.state.errorMessage;
    try {
      const parsed = JSON.parse(this.state.errorMessage) as {
        error?: string;
        operationType?: string;
        path?: string;
      };
      if (parsed && typeof parsed.error === 'string') {
        parsedSummary = `${parsed.error}${parsed.operationType ? ` (operation: ${parsed.operationType}` : ''}${parsed.path ? `, path: ${parsed.path})` : parsed.operationType ? ')' : ''}`;
      }
    } catch {
      // Plain error message
    }

    return (
      <div className="min-h-screen bg-[#090b10] text-slate-100 flex items-center justify-center p-6">
        <div className="max-w-lg w-full bg-[#121621] border border-red-500/30 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-3 text-red-400">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <h1 className="text-lg font-semibold">Command Center Runtime Fault</h1>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed break-words">{parsedSummary}</p>
          <div className="pt-2 flex items-center gap-3">
            <button
              type="button"
              onClick={this.handleReset}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RotateCcw className="w-4 h-4" />
              Recover Session
            </button>
          </div>
        </div>
      </div>
    );
  }
}
