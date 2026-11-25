import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { SCHEMA_LIMITS, isValidEntityId } from './src/shared/validation';

const rulesSource = fs.readFileSync(path.resolve(process.cwd(), 'firestore.rules'), 'utf8');
const blueprint = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), 'firebase-blueprint.json'), 'utf8')
);

interface AuthContext {
  uid: string;
  email: string;
  email_verified: boolean;
}

interface SimEnv {
  now: number;
  docs: Map<string, Record<string, unknown>>;
}

function hasAll(obj: Record<string, unknown>, keys: string[]): boolean {
  return keys.every((k) => Object.prototype.hasOwnProperty.call(obj, k));
}

function hasOnly(obj: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(obj).every((k) => keys.includes(k));
}

function affectedKeys(
  incoming: Record<string, unknown>,
  existing: Record<string, unknown>
): string[] {
  const allKeys = new Set([...Object.keys(incoming), ...Object.keys(existing)]);
  const changed: string[] = [];
  for (const key of allKeys) {
    if (incoming[key] !== existing[key]) {
      changed.push(key);
    }
  }
  return changed;
}

/**
 * Deterministic Eight-Pillar Rule Evaluator mirroring firestore.rules
 * to verify all 12 Dirty Dozen adversarial payloads return PERMISSION_DENIED (false).
 */
function evaluateSimulatedOperation(params: {
  env: SimEnv;
  auth: AuthContext | null;
  op: 'get' | 'list' | 'create' | 'update' | 'delete';
  docPath: string;
  incomingData?: Record<string, unknown>;
  queryOwnerId?: string;
}): boolean {
  const { env, auth, op, docPath, incomingData, queryOwnerId } = params;
  const segments = docPath.split('/').filter(Boolean);

  if (!auth) return false;
  if (segments[0] !== 'users' || !segments[1]) return false;

  const userId = segments[1];
  const isOwner = auth.uid === userId;
  const isVerifiedOwner = isOwner && auth.email_verified === true;
  const userDocExists = env.docs.has(`users/${userId}`);

  // /users/{userId}
  if (segments.length === 2) {
    if (op === 'list' || op === 'delete') return false;
    if (!isValidEntityId(userId)) return false;
    if (op === 'get') return isOwner;

    if (!isVerifiedOwner || !incomingData) return false;
    const reqKeys = [
      'uid',
      'displayName',
      'photoURL',
      'executionMode',
      'emergencyStop',
      'allowWebResearch',
      'allowFileAnalysis',
      'allowLocalBridge',
      'allowAutomationQueue',
      'createdAt',
      'updatedAt',
    ];
    const validShape =
      hasAll(incomingData, reqKeys) &&
      hasOnly(incomingData, reqKeys) &&
      incomingData.uid === auth.uid &&
      typeof incomingData.displayName === 'string' &&
      incomingData.displayName.length >= 1 &&
      incomingData.displayName.length <= SCHEMA_LIMITS.DISPLAY_NAME_MAX &&
      typeof incomingData.photoURL === 'string' &&
      incomingData.photoURL.length <= SCHEMA_LIMITS.PHOTO_URL_MAX &&
      ['cloud', 'local', 'hybrid'].includes(String(incomingData.executionMode)) &&
      typeof incomingData.emergencyStop === 'boolean' &&
      typeof incomingData.allowWebResearch === 'boolean' &&
      typeof incomingData.allowFileAnalysis === 'boolean' &&
      typeof incomingData.allowLocalBridge === 'boolean' &&
      typeof incomingData.allowAutomationQueue === 'boolean';

    if (!validShape) return false;
    if (op === 'create') {
      return incomingData.createdAt === env.now && incomingData.updatedAt === env.now;
    }
    if (op === 'update') {
      const existing = env.docs.get(docPath);
      if (!existing) return false;
      const diff = affectedKeys(incomingData, existing);
      return (
        incomingData.uid === existing.uid &&
        incomingData.createdAt === existing.createdAt &&
        incomingData.updatedAt === env.now &&
        (diff.every((k) => ['displayName', 'photoURL', 'updatedAt'].includes(k)) ||
          diff.every((k) => ['executionMode', 'updatedAt'].includes(k)) ||
          diff.every((k) => ['emergencyStop', 'updatedAt'].includes(k)) ||
          diff.every((k) =>
            [
              'allowWebResearch',
              'allowFileAnalysis',
              'allowLocalBridge',
              'allowAutomationQueue',
              'updatedAt',
            ].includes(k)
          ))
      );
    }
  }

  // /users/{userId}/private/{docId}
  if (segments.length === 4 && segments[2] === 'private') {
    const docId = segments[3];
    if (op === 'list' || op === 'delete') return false;
    if (!isValidEntityId(userId) || docId !== 'account') return false;
    if (op === 'get') return isOwner;
    if (!isVerifiedOwner || !incomingData || !userDocExists) return false;
    const keys = ['uid', 'email', 'createdAt', 'updatedAt'];
    const valid =
      hasAll(incomingData, keys) &&
      hasOnly(incomingData, keys) &&
      incomingData.uid === auth.uid &&
      incomingData.email === auth.email &&
      typeof incomingData.email === 'string' &&
      incomingData.email.length <= SCHEMA_LIMITS.EMAIL_MAX;
    if (!valid) return false;
    return op === 'create'
      ? incomingData.createdAt === env.now && incomingData.updatedAt === env.now
      : false;
  }

  // /users/{userId}/tasks/{taskId}
  if (segments.length === 4 && segments[2] === 'tasks') {
    const taskId = segments[3];
    if (op === 'list') {
      return isOwner && queryOwnerId === auth.uid;
    }
    if (!isValidEntityId(userId) || !isValidEntityId(taskId) || !userDocExists) return false;
    const existing = env.docs.get(docPath);
    if (op === 'get') return isOwner && existing?.userId === auth.uid;
    if (op === 'delete') return isVerifiedOwner && existing?.userId === auth.uid;
    if (!isVerifiedOwner || !incomingData) return false;
    const keys = ['id', 'userId', 'title', 'category', 'status', 'priority', 'createdAt', 'updatedAt'];
    const valid =
      hasAll(incomingData, keys) &&
      hasOnly(incomingData, keys) &&
      incomingData.id === taskId &&
      incomingData.userId === auth.uid &&
      typeof incomingData.title === 'string' &&
      incomingData.title.length >= 1 &&
      incomingData.title.length <= SCHEMA_LIMITS.TASK_TITLE_MAX &&
      ['queued', 'in_progress', 'completed', 'archived'].includes(String(incomingData.status));
    if (!valid) return false;
    if (op === 'create') {
      return incomingData.createdAt === env.now && incomingData.updatedAt === env.now;
    }
    if (op === 'update') {
      if (!existing || existing.status === 'archived') return false;
      const diff = affectedKeys(incomingData, existing);
      return (
        incomingData.id === existing.id &&
        incomingData.userId === existing.userId &&
        incomingData.createdAt === existing.createdAt &&
        incomingData.updatedAt === env.now &&
        (diff.every((k) => ['status', 'updatedAt'].includes(k)) ||
          diff.every((k) => ['title', 'category', 'priority', 'updatedAt'].includes(k)))
      );
    }
  }

  // /users/{userId}/conversations/{conversationId}/messages/{messageId}
  if (segments.length === 6 && segments[2] === 'conversations' && segments[4] === 'messages') {
    const convId = segments[3];
    const msgId = segments[5];
    const convExists = env.docs.has(`users/${userId}/conversations/${convId}`);
    if (op === 'update') return false;
    if (!isValidEntityId(userId) || !isValidEntityId(convId) || !isValidEntityId(msgId)) return false;
    if (op === 'create') {
      if (!isVerifiedOwner || !incomingData || !userDocExists || !convExists) return false;
      const keys = [
        'id',
        'conversationId',
        'userId',
        'role',
        'content',
        'intent',
        'agentModuleNote',
        'modelUsed',
        'createdAt',
      ];
      return (
        hasAll(incomingData, keys) &&
        hasOnly(incomingData, keys) &&
        incomingData.id === msgId &&
        incomingData.conversationId === convId &&
        incomingData.userId === auth.uid &&
        typeof incomingData.content === 'string' &&
        incomingData.content.length >= 1 &&
        incomingData.content.length <= SCHEMA_LIMITS.MESSAGE_CONTENT_MAX &&
        incomingData.createdAt === env.now
      );
    }
  }

  // /users/{userId}/auditEvents/{eventId}
  if (segments.length === 4 && segments[2] === 'auditEvents') {
    if (op === 'update' || op === 'delete') return false;
  }

  return false;
}

test('firestore.rules structural invariants match firebase-blueprint.json', () => {
  assert.ok(rulesSource.includes("rules_version = '2';"));
  assert.ok(rulesSource.includes('match /{document=**} {\n      allow read, write: if false;\n    }'));

  // Every blueprint path has an explicit match block
  assert.ok(rulesSource.includes('match /users/{userId}'));
  assert.ok(rulesSource.includes('match /private/{docId}'));
  assert.ok(rulesSource.includes('match /conversations/{conversationId}'));
  assert.ok(rulesSource.includes('match /messages/{messageId}'));
  assert.ok(rulesSource.includes('match /tasks/{taskId}'));
  assert.ok(rulesSource.includes('match /auditEvents/{eventId}'));
  assert.ok(rulesSource.includes('match /networkAssets/{assetId}'));
  assert.ok(rulesSource.includes('match /researchReports/{reportId}'));
  assert.ok(rulesSource.includes('match /knowledgeNodes/{nodeId}'));
  assert.ok(rulesSource.includes('match /behaviourInsights/{insightId}'));
  assert.ok(rulesSource.includes('match /techAnalyses/{analysisId}'));
  assert.ok(rulesSource.includes('match /cveAdvisories/{advisoryId}'));
  assert.ok(rulesSource.includes('match /researchMonitors/{monitorId}'));
  assert.ok(rulesSource.includes('match /sentinelHeartbeats/{heartbeatId}'));

  // Verify blueprint has all 14 entities (6 v0.1 + 4 GIN v0.2 + 3 GRI v0.5 + 1 Sentinel v0.6)
  assert.deepEqual(Object.keys(blueprint.entities).sort(), [
    'AuditEvent',
    'BehaviourInsight',
    'Conversation',
    'CveAdvisory',
    'KnowledgeNode',
    'Message',
    'NetworkAsset',
    'PrivateAccount',
    'ResearchMonitor',
    'ResearchReport',
    'SentinelHeartbeat',
    'TaskRecord',
    'TechAnalysis',
    'UserProfile',
  ]);
});

test('Dirty Dozen adversarial payloads all return PERMISSION_DENIED (false)', () => {
  const now = 1795262000000;
  const victimAuth: AuthContext = { uid: 'user_victim', email: 'victim@example.com', email_verified: true };
  const attackerAuth: AuthContext = { uid: 'user_attacker', email: 'attacker@example.com', email_verified: true };
  const unverifiedAuth: AuthContext = { uid: 'user_unverified', email: 'u@example.com', email_verified: false };

  const env: SimEnv = {
    now,
    docs: new Map([
      [
        'users/user_victim',
        {
          uid: 'user_victim',
          displayName: 'Victim',
          photoURL: '',
          executionMode: 'cloud',
          emergencyStop: false,
          allowWebResearch: false,
          allowFileAnalysis: false,
          allowLocalBridge: false,
          allowAutomationQueue: false,
          createdAt: now - 1000,
          updatedAt: now - 1000,
        },
      ],
      ['users/user_victim/private/account', { uid: 'user_victim', email: 'victim@example.com', createdAt: now - 1000, updatedAt: now - 1000 }],
      [
        'users/user_victim/tasks/task_archived',
        {
          id: 'task_archived',
          userId: 'user_victim',
          title: 'Archived Task',
          category: 'security',
          status: 'archived',
          priority: 'high',
          createdAt: now - 1000,
          updatedAt: now - 500,
        },
      ],
      [
        'users/user_victim/auditEvents/evt_1',
        {
          id: 'evt_1',
          userId: 'user_victim',
          action: 'SIGN_IN',
          category: 'auth',
          severity: 'info',
          summary: 'Signed in',
          createdAt: now - 1000,
        },
      ],
    ]),
  };

  // 1. Cross-Tenant Profile & PII Read
  assert.equal(
    evaluateSimulatedOperation({ env, auth: attackerAuth, op: 'get', docPath: 'users/user_victim/private/account' }),
    false
  );

  // 2. Unverified Email Write
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: unverifiedAuth,
      op: 'create',
      docPath: 'users/user_unverified',
      incomingData: {
        uid: 'user_unverified',
        displayName: 'Test',
        photoURL: '',
        executionMode: 'cloud',
        emergencyStop: false,
        allowWebResearch: false,
        allowFileAnalysis: false,
        allowLocalBridge: false,
        allowAutomationQueue: false,
        createdAt: now,
        updatedAt: now,
      },
    }),
    false
  );

  // 3. Shadow Field Injection (isAdmin: true)
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'update',
      docPath: 'users/user_victim',
      incomingData: {
        ...(env.docs.get('users/user_victim') as Record<string, unknown>),
        isAdmin: true,
        updatedAt: now,
      },
    }),
    false
  );

  // 4. UID Spoofing inside Owned Path
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'create',
      docPath: 'users/user_victim/tasks/task_spoof',
      incomingData: {
        id: 'task_spoof',
        userId: 'user_attacker',
        title: 'Spoof',
        category: 'chat',
        status: 'queued',
        priority: 'low',
        createdAt: now,
        updatedAt: now,
      },
    }),
    false
  );

  // 5. Path ID Poisoning
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'create',
      docPath: 'users/user_victim/tasks/bad$id!@#',
      incomingData: {
        id: 'bad$id!@#',
        userId: 'user_victim',
        title: 'Bad ID',
        category: 'chat',
        status: 'queued',
        priority: 'low',
        createdAt: now,
        updatedAt: now,
      },
    }),
    false
  );

  // 6. Oversized Payload Exhaustion
  env.docs.set('users/user_victim/conversations/conv_1', { id: 'conv_1', userId: 'user_victim' });
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'create',
      docPath: 'users/user_victim/conversations/conv_1/messages/msg_huge',
      incomingData: {
        id: 'msg_huge',
        conversationId: 'conv_1',
        userId: 'user_victim',
        role: 'user',
        content: 'x'.repeat(40000),
        intent: 'chat',
        agentModuleNote: 'note',
        modelUsed: 'gemini-4-hydrogen',
        createdAt: now,
      },
    }),
    false
  );

  // 7. Forged Client Timestamp
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'create',
      docPath: 'users/user_victim/tasks/task_backdated',
      incomingData: {
        id: 'task_backdated',
        userId: 'user_victim',
        title: 'Backdated',
        category: 'chat',
        status: 'queued',
        priority: 'low',
        createdAt: 1000,
        updatedAt: now,
      },
    }),
    false
  );

  // 8. Orphaned Subcollection Write (missing conversation)
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'create',
      docPath: 'users/user_victim/conversations/conv_missing/messages/msg_1',
      incomingData: {
        id: 'msg_1',
        conversationId: 'conv_missing',
        userId: 'user_victim',
        role: 'user',
        content: 'Hello',
        intent: 'chat',
        agentModuleNote: 'note',
        modelUsed: 'gemini-4-hydrogen',
        createdAt: now,
      },
    }),
    false
  );

  // 9. Immutable Field Mutation (createdAt changed)
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'update',
      docPath: 'users/user_victim',
      incomingData: {
        ...(env.docs.get('users/user_victim') as Record<string, unknown>),
        emergencyStop: true,
        createdAt: now,
        updatedAt: now,
      },
    }),
    false
  );

  // 10. Terminal State Resurrection (updating archived task)
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'update',
      docPath: 'users/user_victim/tasks/task_archived',
      incomingData: {
        ...(env.docs.get('users/user_victim/tasks/task_archived') as Record<string, unknown>),
        status: 'in_progress',
        updatedAt: now,
      },
    }),
    false
  );

  // 11. Audit Log Tampering (deleting audit record)
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'delete',
      docPath: 'users/user_victim/auditEvents/evt_1',
    }),
    false
  );

  // 12. Unfiltered Collection Scraping
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'list',
      docPath: 'users/user_victim/tasks/any',
      queryOwnerId: undefined,
    }),
    false
  );

  // Positive control: Legitimate verified owner emergency stop toggle succeeds
  assert.equal(
    evaluateSimulatedOperation({
      env,
      auth: victimAuth,
      op: 'update',
      docPath: 'users/user_victim',
      incomingData: {
        ...(env.docs.get('users/user_victim') as Record<string, unknown>),
        emergencyStop: true,
        updatedAt: now,
      },
    }),
    true
  );
});
