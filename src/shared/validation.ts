import type {
  AuditCategory,
  AuditSeverity,
  ExecutionMode,
  IntentCategory,
  TaskPriority,
  TaskStatus,
} from './types.ts';

// Exact constants synchronized verbatim with firebase-blueprint.json & firestore.rules
export const SCHEMA_LIMITS = {
  ID_MAX_LENGTH: 128,
  ID_REGEX: /^[a-zA-Z0-9_-]+$/,
  DISPLAY_NAME_MAX: 120,
  PHOTO_URL_MAX: 1024,
  EMAIL_MAX: 320,
  CONVERSATION_TITLE_MAX: 160,
  MESSAGE_PREVIEW_MAX: 300,
  MESSAGE_CONTENT_MAX: 32000,
  AGENT_NOTE_MAX: 400,
  MODEL_USED_MAX: 64,
  TASK_TITLE_MAX: 200,
  AUDIT_ACTION_MAX: 80,
  AUDIT_SUMMARY_MAX: 320,
} as const;

export const ALLOWED_INTENTS: readonly IntentCategory[] = [
  'chat',
  'research',
  'coding',
  'vision',
  'security',
  'automation',
];

export const ALLOWED_EXECUTION_MODES: readonly ExecutionMode[] = [
  'cloud',
  'local',
  'hybrid',
];

export const ALLOWED_TASK_STATUSES: readonly TaskStatus[] = [
  'queued',
  'in_progress',
  'completed',
  'archived',
];

export const ALLOWED_TASK_PRIORITIES: readonly TaskPriority[] = [
  'low',
  'medium',
  'high',
];

export const ALLOWED_AUDIT_CATEGORIES: readonly AuditCategory[] = [
  'auth',
  'chat',
  'security',
  'settings',
  'memory',
  'task',
  'network',
  'research',
  'knowledge',
  'behaviour',
];

export const ALLOWED_AUDIT_SEVERITIES: readonly AuditSeverity[] = [
  'info',
  'warning',
  'critical',
];

export function isValidEntityId(id: unknown): id is string {
  return (
    typeof id === 'string' &&
    id.length >= 1 &&
    id.length <= SCHEMA_LIMITS.ID_MAX_LENGTH &&
    SCHEMA_LIMITS.ID_REGEX.test(id)
  );
}

export function createSafeId(prefix: string): string {
  const cleanPrefix = prefix.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 20) || 'item';
  const rand =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID().replace(/[^a-zA-Z0-9_-]/g, '')
      : `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  return `${cleanPrefix}_${rand}`.slice(0, SCHEMA_LIMITS.ID_MAX_LENGTH);
}

export function sanitizeBoundedString(input: string, maxLength: number, fallback = ''): string {
  const trimmed = input.trim();
  if (!trimmed) {
    return fallback.slice(0, maxLength);
  }
  return trimmed.slice(0, maxLength);
}

export function validateTaskInput(title: string): { valid: boolean; error?: string; sanitizedTitle: string } {
  const trimmed = title.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: 'Task title is required.', sanitizedTitle: '' };
  }
  if (trimmed.length > SCHEMA_LIMITS.TASK_TITLE_MAX) {
    return {
      valid: false,
      error: `Task title must be ${SCHEMA_LIMITS.TASK_TITLE_MAX} characters or fewer.`,
      sanitizedTitle: trimmed.slice(0, SCHEMA_LIMITS.TASK_TITLE_MAX),
    };
  }
  return { valid: true, sanitizedTitle: trimmed };
}

export function validateChatPrompt(prompt: string): { valid: boolean; error?: string; sanitizedPrompt: string } {
  const trimmed = prompt.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: 'Enter a message before sending.', sanitizedPrompt: '' };
  }
  if (trimmed.length > SCHEMA_LIMITS.MESSAGE_CONTENT_MAX) {
    return {
      valid: false,
      error: `Message exceeds the ${SCHEMA_LIMITS.MESSAGE_CONTENT_MAX.toLocaleString()}-character safety limit.`,
      sanitizedPrompt: trimmed.slice(0, SCHEMA_LIMITS.MESSAGE_CONTENT_MAX),
    };
  }
  return { valid: true, sanitizedPrompt: trimmed };
}

export function isSafeExternalUrl(rawUrl: string | undefined): boolean {
  if (!rawUrl) return false;
  const trimmed = rawUrl.trim();
  if (trimmed.startsWith('#') || trimmed.startsWith('/')) {
    return !trimmed.startsWith('//');
  }
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' || parsed.protocol === 'mailto:';
  } catch {
    return false;
  }
}
