import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  onAuthStateChanged,
  signInWithPopup,
  signOut as firebaseSignOut,
  type User,
} from 'firebase/auth';
import {
  Timestamp,
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  writeBatch,
} from 'firebase/firestore';
import {
  OperationType,
  auth,
  db,
  googleProvider,
  handleFirestoreError,
  testFirestoreConnection,
} from '../lib/firebase';
import {
  GOD_CORE_MODEL,
  deriveConversationTitle,
  evaluateGodCoreRouting,
} from '../shared/godCoreLogic';
import {
  SCHEMA_LIMITS,
  createSafeId,
  sanitizeBoundedString,
  validateChatPrompt,
  validateTaskInput,
} from '../shared/validation';
import type {
  AuditCategory,
  AuditEventRecord,
  AuditSeverity,
  ConversationRecord,
  ExecutionMode,
  IntentCategory,
  IntentClassificationResult,
  MessageRecord,
  NavSection,
  ProviderDescriptor,
  TaskPriority,
  TaskRecord,
  TaskStatus,
  UserProfileRecord,
} from '../shared/types';

import type { SensorNodeInterfaceSpec } from '../shared/ginTypes';

interface SystemServerInfo {
  name: string;
  version: string;
  ginVersion?: string;
  griVersion?: string;
  coreModel: string;
  geminiConfigured: boolean;
  searchGroundingEnabled?: boolean;
  pairedLocalNodes: number;
  rateLimitPerMinute?: number;
  providers: ProviderDescriptor[];
  sensorInterfaces?: SensorNodeInterfaceSpec[];
}

export type CapabilityPermissionKey =
  | 'allowWebResearch'
  | 'allowFileAnalysis'
  | 'allowLocalBridge'
  | 'allowAutomationQueue';

interface GodWorkspaceContextValue {
  authReady: boolean;
  firebaseUser: User | null;
  isPreviewMode: boolean;
  enterPreviewMode: () => void;
  exitPreviewMode: () => void;
  signInWithGoogle: () => Promise<void>;
  signOutUser: () => Promise<void>;
  authError: string | null;

  activeSection: NavSection;
  setActiveSection: (section: NavSection) => void;

  profile: UserProfileRecord;
  privateEmail: string;
  systemInfo: SystemServerInfo | null;

  conversations: ConversationRecord[];
  activeConversationId: string | null;
  selectConversation: (conversationId: string | null) => void;
  startNewConversation: (prefillPrompt?: string) => void;
  prefillChatInput: string;
  clearPrefillChatInput: () => void;
  messages: MessageRecord[];
  deleteConversation: (conversationId: string) => Promise<void>;

  isStreamingChat: boolean;
  streamingText: string;
  streamingMeta: IntentClassificationResult | null;
  chatError: string | null;
  clearChatError: () => void;
  sendChatMessage: (prompt: string) => Promise<void>;
  abortActiveStream: () => void;

  tasks: TaskRecord[];
  createTask: (input: {
    title: string;
    category: IntentCategory;
    priority: TaskPriority;
  }) => Promise<{ ok: boolean; error?: string }>;
  updateTaskStatus: (taskId: string, status: TaskStatus) => Promise<void>;
  deleteTask: (taskId: string) => Promise<void>;

  auditEvents: AuditEventRecord[];
  bootstrapReadyUid: string | null;
  recordAuditEvent: (params: {
    action: string;
    category: AuditCategory;
    severity: AuditSeverity;
    summary: string;
  }) => Promise<void>;
  setExecutionMode: (mode: ExecutionMode) => Promise<void>;
  toggleEmergencyStop: (engaged: boolean) => Promise<void>;
  updateCapabilityPermission: (
    key: CapabilityPermissionKey,
    enabled: boolean
  ) => Promise<void>;
}

const GodWorkspaceContext = createContext<GodWorkspaceContextValue | null>(null);

function tsToMillis(val: unknown, fallback: number): number {
  if (val instanceof Timestamp) {
    return val.toMillis();
  }
  if (val && typeof val === 'object' && 'seconds' in val && typeof (val as { seconds: unknown }).seconds === 'number') {
    return (val as { seconds: number }).seconds * 1000;
  }
  if (typeof val === 'number') return val;
  return fallback;
}

const INITIAL_PREVIEW_NOW = 1795261800000;

function createInitialPreviewSeed() {
  const profile: UserProfileRecord = {
    uid: 'preview_operator',
    displayName: 'Preview Session',
    photoURL: '',
    executionMode: 'cloud',
    emergencyStop: false,
    allowWebResearch: false,
    allowFileAnalysis: true,
    allowLocalBridge: false,
    allowAutomationQueue: false,
    createdAtMs: INITIAL_PREVIEW_NOW - 3600_000,
    updatedAtMs: INITIAL_PREVIEW_NOW - 600_000,
  };

  const conv1Id = 'conv_preview_arch';
  const conv2Id = 'conv_preview_sec';

  const conversations: ConversationRecord[] = [
    {
      id: conv1Id,
      userId: 'preview_operator',
      title: 'Hybrid Cloud + Local Node Enrollment Spec',
      lastIntent: 'security',
      lastMessagePreview:
        'Local nodes initiate outbound TLS 1.3 WSS tunnels using single-use enrollment tokens...',
      messageCount: 2,
      createdAtMs: INITIAL_PREVIEW_NOW - 2400_000,
      updatedAtMs: INITIAL_PREVIEW_NOW - 900_000,
    },
    {
      id: conv2Id,
      userId: 'preview_operator',
      title: 'TypeScript Provider Abstraction Pattern',
      lastIntent: 'coding',
      lastMessagePreview:
        'Define an IntelligenceProviderAdapter with async generator streaming so Gemini and Ollama share...',
      messageCount: 2,
      createdAtMs: INITIAL_PREVIEW_NOW - 5400_000,
      updatedAtMs: INITIAL_PREVIEW_NOW - 3200_000,
    },
  ];

  const messagesByConv: Record<string, MessageRecord[]> = {
    [conv1Id]: [
      {
        id: 'msg_prev_1',
        conversationId: conv1Id,
        userId: 'preview_operator',
        role: 'user',
        content:
          'How does AI GOD (GOD-X) securely enroll a Windows or Kali Linux workstation without exposing local ports?',
        intent: 'security',
        agentModuleNote: 'Operator Prompt',
        modelUsed: 'operator',
        createdAtMs: INITIAL_PREVIEW_NOW - 2400_000,
      },
      {
        id: 'msg_prev_2',
        conversationId: conv1Id,
        userId: 'preview_operator',
        role: 'assistant',
        content: `### Outbound-Only Zero-Trust Node Enrollment (v0.2 Architecture)

A cloud-hosted web application must **never** assume direct reachability to \`127.0.0.1\` or private RFC1918 LAN addresses. AI GOD enforces a 4-step outbound enrollment handshake:

1. **Scoped Enrollment Token**: You mint a single-use, 5-minute token bound to your Firebase UID inside **Settings → Hybrid Node Enrollment**.
2. **Outbound mTLS / WSS Tunnel**: An unprivileged local daemon on Windows or Kali Linux initiates an outbound TLS 1.3 WebSocket connection to the cloud relay—zero inbound firewall ports are opened.
3. **Ed25519 Device Attestation**: The node signs challenges with a hardware-backed or OS-keychain keypair.
4. **Explicit Capability Gating**: Local inference remains **disabled** in v0.1 until a node is paired and approved in the **Security Center**.`,
        intent: 'security',
        agentModuleNote:
          'Classified: Security · Defensive reasoning via Gemini Cloud (gemini-4-hydrogen). Active host telemetry Agent is Prototype (v0.2)',
        modelUsed: GOD_CORE_MODEL,
        createdAtMs: INITIAL_PREVIEW_NOW - 900_000,
      },
    ],
    [conv2Id]: [
      {
        id: 'msg_prev_3',
        conversationId: conv2Id,
        userId: 'preview_operator',
        role: 'user',
        content: 'Show the TypeScript interface used to decouple Gemini Cloud from future Ollama nodes.',
        intent: 'coding',
        agentModuleNote: 'Operator Prompt',
        modelUsed: 'operator',
        createdAtMs: INITIAL_PREVIEW_NOW - 5400_000,
      },
      {
        id: 'msg_prev_4',
        conversationId: conv2Id,
        userId: 'preview_operator',
        role: 'assistant',
        content: `\`\`\`typescript
export interface IntelligenceProviderAdapter {
  readonly id: string;
  readonly name: string;
  readonly environment: 'cloud' | 'local';
  isAvailable(): boolean;
  streamCompletion(input: StreamCompletionInput): AsyncGenerator<string, void, unknown>;
}
\`\`\`

In **v0.1**, \`GeminiCloudProviderAdapter\` is active on the server while \`OllamaLocalBridgeProviderAdapter.isAvailable()\` returns \`false\` until a local node completes pairing.`,
        intent: 'coding',
        agentModuleNote:
          'Classified: Coding · Answered via Gemini Cloud (gemini-4-hydrogen). Sandboxed code runner Agent is Prototype (v0.2)',
        modelUsed: GOD_CORE_MODEL,
        createdAtMs: INITIAL_PREVIEW_NOW - 3200_000,
      },
    ],
  };

  const tasks: TaskRecord[] = [
    {
      id: 'task_prev_1',
      userId: 'preview_operator',
      title: 'Verify Eight-Pillar Firestore tenant isolation rules',
      category: 'security',
      status: 'completed',
      priority: 'high',
      createdAtMs: INITIAL_PREVIEW_NOW - 7200_000,
      updatedAtMs: INITIAL_PREVIEW_NOW - 3600_000,
    },
    {
      id: 'task_prev_2',
      userId: 'preview_operator',
      title: 'Review outbound WSS mTLS node enrollment specification',
      category: 'research',
      status: 'in_progress',
      priority: 'high',
      createdAtMs: INITIAL_PREVIEW_NOW - 3000_000,
      updatedAtMs: INITIAL_PREVIEW_NOW - 1200_000,
    },
    {
      id: 'task_prev_3',
      userId: 'preview_operator',
      title: 'Benchmark Ollama Qwen2.5-Coder latency once workstation pairs',
      category: 'coding',
      status: 'queued',
      priority: 'medium',
      createdAtMs: INITIAL_PREVIEW_NOW - 1800_000,
      updatedAtMs: INITIAL_PREVIEW_NOW - 1800_000,
    },
  ];

  const auditEvents: AuditEventRecord[] = [
    {
      id: 'audit_prev_1',
      userId: 'preview_operator',
      action: 'PREVIEW_SESSION_INITIALIZED',
      category: 'auth',
      severity: 'info',
      summary: 'Initialized local in-memory preview workspace. Sign in with Google for Cloud Firestore persistence.',
      createdAtMs: INITIAL_PREVIEW_NOW - 600_000,
    },
    {
      id: 'audit_prev_2',
      userId: 'preview_operator',
      action: 'LOCAL_BRIDGE_LOCKED',
      category: 'security',
      severity: 'info',
      summary: 'Verified 0 local nodes paired; local execution path remains disabled by default.',
      createdAtMs: INITIAL_PREVIEW_NOW - 1800_000,
    },
  ];

  return { profile, conversations, messagesByConv, tasks, auditEvents };
}

export function GodWorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [authReady, setAuthReady] = useState(false);
  const [firebaseUser, setFirebaseUser] = useState<User | null>(null);
  const [bootstrapReadyUid, setBootstrapReadyUid] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  const [isPreviewMode, setIsPreviewMode] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    const params = new URLSearchParams(window.location.search);
    return params.get('autostart') === '1';
  });

  const [activeSection, setActiveSection] = useState<NavSection>('dashboard');
  const [systemInfo, setSystemInfo] = useState<SystemServerInfo | null>(null);

  // Preview state (used only when isPreviewMode && !firebaseUser)
  const previewSeed = useMemo(() => createInitialPreviewSeed(), []);
  const [previewProfile, setPreviewProfile] = useState<UserProfileRecord>(previewSeed.profile);
  const [previewConversations, setPreviewConversations] = useState<ConversationRecord[]>(
    previewSeed.conversations
  );
  const [previewMessagesMap, setPreviewMessagesMap] = useState<Record<string, MessageRecord[]>>(
    previewSeed.messagesByConv
  );
  const [previewTasks, setPreviewTasks] = useState<TaskRecord[]>(previewSeed.tasks);
  const [previewAuditEvents, setPreviewAuditEvents] = useState<AuditEventRecord[]>(
    previewSeed.auditEvents
  );

  // Live Firestore state (used when firebaseUser !== null)
  const [cloudProfile, setCloudProfile] = useState<UserProfileRecord | null>(null);
  const [privateEmail, setPrivateEmail] = useState<string>('');
  const [cloudConversations, setCloudConversations] = useState<ConversationRecord[]>([]);
  const [cloudMessages, setCloudMessages] = useState<MessageRecord[]>([]);
  const [cloudTasks, setCloudTasks] = useState<TaskRecord[]>([]);
  const [cloudAuditEvents, setCloudAuditEvents] = useState<AuditEventRecord[]>([]);

  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [prefillChatInput, setPrefillChatInput] = useState<string>('');

  const [isStreamingChat, setIsStreamingChat] = useState(false);
  const [streamingText, setStreamingText] = useState('');
  const [streamingMeta, setStreamingMeta] = useState<IntentClassificationResult | null>(null);
  const [chatError, setChatError] = useState<string | null>(null);
  const streamAbortRef = useRef<AbortController | null>(null);

  // Fetch non-sensitive backend system info
  useEffect(() => {
    let cancelled = false;
    fetch('/api/system/info')
      .then((res) => (res.ok ? res.json() : null))
      .then((data: SystemServerInfo | null) => {
        if (!cancelled && data) {
          setSystemInfo(data);
        }
      })
      .catch(() => {
        // Non-fatal
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Validate Firestore connection & listen to Firebase Auth
  useEffect(() => {
    void testFirestoreConnection();

    const unsub = onAuthStateChanged(auth, async (user) => {
      setFirebaseUser(user);
      setAuthError(null);

      if (!user) {
        setBootstrapReadyUid(null);
        setCloudProfile(null);
        setPrivateEmail('');
        setCloudConversations([]);
        setCloudMessages([]);
        setCloudTasks([]);
        setCloudAuditEvents([]);
        setAuthReady(true);
        return;
      }

      setIsPreviewMode(false);

      const userPath = `users/${user.uid}`;
      const privatePath = `users/${user.uid}/private/account`;

      try {
        const userRef = doc(db, 'users', user.uid);
        const existingSnap = await getDoc(userRef);
        const safeDisplayName = sanitizeBoundedString(
          user.displayName || user.email?.split('@')[0] || 'Operator',
          SCHEMA_LIMITS.DISPLAY_NAME_MAX,
          'Operator'
        );
        const safePhotoUrl = sanitizeBoundedString(
          user.photoURL || '',
          SCHEMA_LIMITS.PHOTO_URL_MAX,
          ''
        );

        if (!existingSnap.exists()) {
          await setDoc(userRef, {
            uid: user.uid,
            displayName: safeDisplayName,
            photoURL: safePhotoUrl,
            executionMode: 'cloud',
            emergencyStop: false,
            allowWebResearch: false,
            allowFileAnalysis: true,
            allowLocalBridge: false,
            allowAutomationQueue: false,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          });

          if (user.email) {
            await setDoc(doc(db, 'users', user.uid, 'private', 'account'), {
              uid: user.uid,
              email: user.email.slice(0, SCHEMA_LIMITS.EMAIL_MAX),
              createdAt: serverTimestamp(),
              updatedAt: serverTimestamp(),
            });
          }

          const initAuditId = createSafeId('evt');
          await setDoc(doc(db, 'users', user.uid, 'auditEvents', initAuditId), {
            id: initAuditId,
            userId: user.uid,
            action: 'WORKSPACE_PROVISIONED',
            category: 'auth',
            severity: 'info',
            summary: 'Initialized isolated Cloud Firestore workspace and security profile.',
            createdAt: serverTimestamp(),
          });
        } else {
          await updateDoc(userRef, {
            displayName: safeDisplayName,
            photoURL: safePhotoUrl,
            updatedAt: serverTimestamp(),
          });

          if (user.email) {
            const privRef = doc(db, 'users', user.uid, 'private', 'account');
            const privSnap = await getDoc(privRef);
            if (!privSnap.exists()) {
              await setDoc(privRef, {
                uid: user.uid,
                email: user.email.slice(0, SCHEMA_LIMITS.EMAIL_MAX),
                createdAt: serverTimestamp(),
                updatedAt: serverTimestamp(),
              });
            }
          }
        }

        setBootstrapReadyUid(user.uid);
      } catch (err) {
        setAuthReady(true);
        handleFirestoreError(err, OperationType.WRITE, `${userPath} | ${privatePath}`);
      }

      setAuthReady(true);
    });

    return () => unsub();
  }, []);

  // Attach real-time Firestore listeners once authenticated & bootstrapped
  useEffect(() => {
    if (!firebaseUser || bootstrapReadyUid !== firebaseUser.uid) {
      return;
    }

    const uid = firebaseUser.uid;
    const unsubs: Array<() => void> = [];

    // 1. UserProfile listener
    const userPath = `users/${uid}`;
    unsubs.push(
      onSnapshot(
        doc(db, 'users', uid),
        (snap) => {
          if (!snap.exists()) return;
          const d = snap.data();
          const now = Date.now();
          setCloudProfile({
            uid: String(d.uid),
            displayName: String(d.displayName || 'Operator'),
            photoURL: String(d.photoURL || ''),
            executionMode: (d.executionMode as ExecutionMode) || 'cloud',
            emergencyStop: Boolean(d.emergencyStop),
            allowWebResearch: Boolean(d.allowWebResearch),
            allowFileAnalysis: Boolean(d.allowFileAnalysis),
            allowLocalBridge: Boolean(d.allowLocalBridge),
            allowAutomationQueue: Boolean(d.allowAutomationQueue),
            createdAtMs: tsToMillis(d.createdAt, now),
            updatedAtMs: tsToMillis(d.updatedAt, now),
          });
        },
        (err) => handleFirestoreError(err, OperationType.GET, userPath)
      )
    );

    // 2. PrivateAccount PII listener
    const privPath = `users/${uid}/private/account`;
    unsubs.push(
      onSnapshot(
        doc(db, 'users', uid, 'private', 'account'),
        (snap) => {
          if (snap.exists()) {
            setPrivateEmail(String(snap.data().email || firebaseUser.email || ''));
          } else {
            setPrivateEmail(firebaseUser.email || '');
          }
        },
        (err) => handleFirestoreError(err, OperationType.GET, privPath)
      )
    );

    // 3. Conversations listener (where userId == uid satisfies Pillar 8 list rule without composite index)
    const convsPath = `users/${uid}/conversations`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'conversations'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: ConversationRecord[] = snap.docs.map((docSnap) => {
            const d = docSnap.data();
            return {
              id: docSnap.id,
              userId: String(d.userId),
              title: String(d.title || 'Untitled Thread'),
              lastIntent: (d.lastIntent as IntentCategory) || 'chat',
              lastMessagePreview: String(d.lastMessagePreview || ''),
              messageCount: Number(d.messageCount || 0),
              createdAtMs: tsToMillis(d.createdAt, now),
              updatedAtMs: tsToMillis(d.updatedAt, now),
            };
          });
          items.sort((a, b) => b.updatedAtMs - a.updatedAtMs);
          setCloudConversations(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, convsPath)
      )
    );

    // 4. Tasks listener
    const tasksPath = `users/${uid}/tasks`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'tasks'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: TaskRecord[] = snap.docs.map((docSnap) => {
            const d = docSnap.data();
            return {
              id: docSnap.id,
              userId: String(d.userId),
              title: String(d.title || ''),
              category: (d.category as IntentCategory) || 'chat',
              status: (d.status as TaskStatus) || 'queued',
              priority: (d.priority as TaskPriority) || 'medium',
              createdAtMs: tsToMillis(d.createdAt, now),
              updatedAtMs: tsToMillis(d.updatedAt, now),
            };
          });
          items.sort((a, b) => b.updatedAtMs - a.updatedAtMs);
          setCloudTasks(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, tasksPath)
      )
    );

    // 5. AuditEvents listener
    const auditPath = `users/${uid}/auditEvents`;
    unsubs.push(
      onSnapshot(
        query(collection(db, 'users', uid, 'auditEvents'), where('userId', '==', uid)),
        (snap) => {
          const now = Date.now();
          const items: AuditEventRecord[] = snap.docs.map((docSnap) => {
            const d = docSnap.data();
            return {
              id: docSnap.id,
              userId: String(d.userId),
              action: String(d.action || 'EVENT'),
              category: (d.category as AuditCategory) || 'security',
              severity: (d.severity as AuditSeverity) || 'info',
              summary: String(d.summary || ''),
              createdAtMs: tsToMillis(d.createdAt, now),
            };
          });
          items.sort((a, b) => b.createdAtMs - a.createdAtMs);
          setCloudAuditEvents(items);
        },
        (err) => handleFirestoreError(err, OperationType.LIST, auditPath)
      )
    );

    return () => {
      for (const u of unsubs) u();
    };
  }, [firebaseUser, bootstrapReadyUid]);

  // Listen to active conversation's messages in Firestore
  useEffect(() => {
    if (!firebaseUser || bootstrapReadyUid !== firebaseUser.uid || !activeConversationId) {
      setCloudMessages([]);
      return;
    }

    const uid = firebaseUser.uid;
    const msgsPath = `users/${uid}/conversations/${activeConversationId}/messages`;
    const unsub = onSnapshot(
      query(
        collection(db, 'users', uid, 'conversations', activeConversationId, 'messages'),
        where('userId', '==', uid)
      ),
      (snap) => {
        const now = Date.now();
        const items: MessageRecord[] = snap.docs.map((docSnap) => {
          const d = docSnap.data();
          return {
            id: docSnap.id,
            conversationId: String(d.conversationId),
            userId: String(d.userId),
            role: d.role === 'assistant' ? 'assistant' : 'user',
            content: String(d.content || ''),
            intent: (d.intent as IntentCategory) || 'chat',
            agentModuleNote: String(d.agentModuleNote || ''),
            modelUsed: String(d.modelUsed || GOD_CORE_MODEL),
            createdAtMs: tsToMillis(d.createdAt, now),
          };
        });
        items.sort((a, b) => a.createdAtMs - b.createdAtMs);
        setCloudMessages(items);
      },
      (err) => handleFirestoreError(err, OperationType.LIST, msgsPath)
    );

    return () => unsub();
  }, [firebaseUser, bootstrapReadyUid, activeConversationId]);

  // Auto-select most recent conversation in preview mode if none selected
  useEffect(() => {
    if (!firebaseUser && isPreviewMode && activeConversationId === null && previewConversations.length > 0) {
      setActiveConversationId(previewConversations[0].id);
    }
  }, [firebaseUser, isPreviewMode, activeConversationId, previewConversations]);

  const recordAuditEvent = useCallback(
    async (params: {
      action: string;
      category: AuditCategory;
      severity: AuditSeverity;
      summary: string;
    }) => {
      const action = sanitizeBoundedString(params.action, SCHEMA_LIMITS.AUDIT_ACTION_MAX, 'ACTION');
      const summary = sanitizeBoundedString(params.summary, SCHEMA_LIMITS.AUDIT_SUMMARY_MAX, 'Event recorded.');

      if (!firebaseUser) {
        const evt: AuditEventRecord = {
          id: createSafeId('evt'),
          userId: 'preview_operator',
          action,
          category: params.category,
          severity: params.severity,
          summary,
          createdAtMs: Date.now(),
        };
        setPreviewAuditEvents((prev) => [evt, ...prev]);
        return;
      }

      const evtId = createSafeId('evt');
      const path = `users/${firebaseUser.uid}/auditEvents/${evtId}`;
      try {
        await setDoc(doc(db, 'users', firebaseUser.uid, 'auditEvents', evtId), {
          id: evtId,
          userId: firebaseUser.uid,
          action,
          category: params.category,
          severity: params.severity,
          summary,
          createdAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, path);
      }
    },
    [firebaseUser]
  );

  const signInWithGoogle = useCallback(async () => {
    setAuthError(null);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!msg.includes('popup-closed-by-user')) {
        setAuthError(msg);
      }
    }
  }, []);

  const signOutUser = useCallback(async () => {
    streamAbortRef.current?.abort();
    setActiveConversationId(null);
    setIsPreviewMode(false);
    await firebaseSignOut(auth);
  }, []);

  const enterPreviewMode = useCallback(() => {
    setAuthError(null);
    setIsPreviewMode(true);
    if (previewConversations.length > 0) {
      setActiveConversationId(previewConversations[0].id);
    }
  }, [previewConversations]);

  const exitPreviewMode = useCallback(() => {
    setIsPreviewMode(false);
  }, []);

  const activeProfile: UserProfileRecord = firebaseUser
    ? cloudProfile || {
        uid: firebaseUser.uid,
        displayName: firebaseUser.displayName || 'Operator',
        photoURL: firebaseUser.photoURL || '',
        executionMode: 'cloud',
        emergencyStop: false,
        allowWebResearch: false,
        allowFileAnalysis: true,
        allowLocalBridge: false,
        allowAutomationQueue: false,
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
      }
    : previewProfile;

  const conversations = firebaseUser ? cloudConversations : previewConversations;
  const messages = firebaseUser
    ? cloudMessages
    : activeConversationId
      ? previewMessagesMap[activeConversationId] || []
      : [];
  const tasks = firebaseUser ? cloudTasks : previewTasks;
  const auditEvents = firebaseUser ? cloudAuditEvents : previewAuditEvents;

  const selectConversation = useCallback((conversationId: string | null) => {
    setChatError(null);
    setActiveConversationId(conversationId);
  }, []);

  const startNewConversation = useCallback((prefillPrompt?: string) => {
    setChatError(null);
    setActiveConversationId(null);
    if (typeof prefillPrompt === 'string') {
      setPrefillChatInput(prefillPrompt);
    }
    setActiveSection('chat');
  }, []);

  const clearPrefillChatInput = useCallback(() => {
    setPrefillChatInput('');
  }, []);

  const clearChatError = useCallback(() => {
    setChatError(null);
  }, []);

  const abortActiveStream = useCallback(() => {
    if (streamAbortRef.current) {
      streamAbortRef.current.abort();
      streamAbortRef.current = null;
    }
    setIsStreamingChat(false);
    setStreamingText('');
    setStreamingMeta(null);
  }, []);

  const sendChatMessage = useCallback(
    async (rawPrompt: string) => {
      setChatError(null);
      const validation = validateChatPrompt(rawPrompt);
      if (!validation.valid) {
        setChatError(validation.error || 'Enter a message before sending.');
        return;
      }

      const prompt = validation.sanitizedPrompt;
      const preflight = evaluateGodCoreRouting({
        prompt,
        executionMode: activeProfile.executionMode,
        emergencyStop: activeProfile.emergencyStop,
        pairedLocalNodesCount: 0,
      });

      if (preflight.executedBy !== 'god-core-gemini-cloud') {
        setChatError(preflight.policyBlockedReason || 'Execution blocked by GOD Core policy.');
        await recordAuditEvent({
          action:
            preflight.executedBy === 'blocked-policy'
              ? 'SECURITY_POLICY_BLOCKED'
              : preflight.executedBy === 'blocked-emergency-stop'
                ? 'EMERGENCY_STOP_REJECTED_PROMPT'
                : 'UNPAIRED_LOCAL_MODE_BLOCKED',
          category: 'security',
          severity: preflight.executedBy === 'blocked-policy' ? 'critical' : 'warning',
          summary: `${preflight.agentModuleNote} (${prompt.slice(0, 90)})`,
        });
        return;
      }

      // Preview session: honest auth notice without faking Gemini output
      if (!firebaseUser) {
        setChatError(
          'Live Gemini Cloud execution requires Google Sign-In so your Firebase ID token can authenticate against the server-side GOD Core endpoint and save encrypted history to Cloud Firestore.'
        );
        return;
      }

      const uid = firebaseUser.uid;
      let convId = activeConversationId;
      let currentMessageCount = 0;
      let currentTitle = deriveConversationTitle(prompt);

      if (!convId) {
        convId = createSafeId('conv');
        const convPath = `users/${uid}/conversations/${convId}`;
        try {
          await setDoc(doc(db, 'users', uid, 'conversations', convId), {
            id: convId,
            userId: uid,
            title: sanitizeBoundedString(currentTitle, SCHEMA_LIMITS.CONVERSATION_TITLE_MAX, 'New Thread'),
            lastIntent: preflight.intent,
            lastMessagePreview: sanitizeBoundedString(prompt, SCHEMA_LIMITS.MESSAGE_PREVIEW_MAX, ''),
            messageCount: 1,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          });
          currentMessageCount = 1;
          setActiveConversationId(convId);
        } catch (err) {
          handleFirestoreError(err, OperationType.CREATE, convPath);
        }
      } else {
        const existingConv = cloudConversations.find((c) => c.id === convId);
        currentMessageCount = (existingConv?.messageCount || cloudMessages.length) + 1;
        currentTitle = existingConv?.title || currentTitle;
      }

      // Persist user message
      const userMsgId = createSafeId('msg');
      const userMsgPath = `users/${uid}/conversations/${convId}/messages/${userMsgId}`;
      try {
        await setDoc(doc(db, 'users', uid, 'conversations', convId, 'messages', userMsgId), {
          id: userMsgId,
          conversationId: convId,
          userId: uid,
          role: 'user',
          content: prompt,
          intent: preflight.intent,
          agentModuleNote: 'Operator Input',
          modelUsed: 'operator',
          createdAt: serverTimestamp(),
        });

        await updateDoc(doc(db, 'users', uid, 'conversations', convId), {
          title: sanitizeBoundedString(currentTitle, SCHEMA_LIMITS.CONVERSATION_TITLE_MAX, 'Thread'),
          lastIntent: preflight.intent,
          lastMessagePreview: sanitizeBoundedString(prompt, SCHEMA_LIMITS.MESSAGE_PREVIEW_MAX, ''),
          messageCount: currentMessageCount,
          updatedAt: serverTimestamp(),
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.WRITE, userMsgPath);
      }

      // Stream response from server-side GOD Core
      const controller = new AbortController();
      streamAbortRef.current = controller;
      setIsStreamingChat(true);
      setStreamingText('');
      setStreamingMeta(preflight);

      let accumulated = '';
      let finalIntent: IntentCategory = preflight.intent;
      let finalNote = preflight.agentModuleNote;
      let finalModel = GOD_CORE_MODEL;

      try {
        const idToken = await firebaseUser.getIdToken();
        const historyPayload = cloudMessages.slice(-14).map((m) => ({
          role: m.role,
          content: m.content,
        }));

        const response = await fetch('/api/god-core/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${idToken}`,
          },
          body: JSON.stringify({
            message: prompt,
            history: historyPayload,
            executionMode: activeProfile.executionMode,
            emergencyStop: activeProfile.emergencyStop,
          }),
          signal: controller.signal,
        });

        if (!response.ok || !response.body) {
          const errPayload = (await response.json().catch(() => ({}))) as { error?: string };
          throw new Error(errPayload.error || `GOD Core request failed (${response.status}).`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          const blocks = buffer.split('\n\n');
          buffer = blocks.pop() || '';

          for (const block of blocks) {
            const lines = block.split('\n');
            let eventType = 'message';
            let dataRaw = '';
            for (const line of lines) {
              if (line.startsWith('event:')) {
                eventType = line.slice(6).trim();
              } else if (line.startsWith('data:')) {
                dataRaw += line.slice(5).trim();
              }
            }
            if (!dataRaw) continue;
            const parsed = JSON.parse(dataRaw) as Record<string, unknown>;

            if (eventType === 'meta') {
              const meta = parsed as unknown as IntentClassificationResult;
              finalIntent = meta.intent;
              finalNote = meta.agentModuleNote;
              setStreamingMeta(meta);
            } else if (eventType === 'delta') {
              const deltaText = typeof parsed.text === 'string' ? parsed.text : '';
              accumulated += deltaText;
              setStreamingText(accumulated);
            } else if (eventType === 'done') {
              if (typeof parsed.modelUsed === 'string') finalModel = parsed.modelUsed;
              if (typeof parsed.agentModuleNote === 'string') finalNote = parsed.agentModuleNote;
            } else if (eventType === 'error') {
              throw new Error(typeof parsed.error === 'string' ? parsed.error : 'GOD Core stream error.');
            }
          }
        }

        const cleanedOutput = sanitizeBoundedString(
          accumulated,
          SCHEMA_LIMITS.MESSAGE_CONTENT_MAX,
          'No response content returned by model.'
        );

        const assistantMsgId = createSafeId('msg');
        const assistantPath = `users/${uid}/conversations/${convId}/messages/${assistantMsgId}`;

        try {
          await setDoc(doc(db, 'users', uid, 'conversations', convId, 'messages', assistantMsgId), {
            id: assistantMsgId,
            conversationId: convId,
            userId: uid,
            role: 'assistant',
            content: cleanedOutput,
            intent: finalIntent,
            agentModuleNote: sanitizeBoundedString(finalNote, SCHEMA_LIMITS.AGENT_NOTE_MAX, 'GOD Core'),
            modelUsed: sanitizeBoundedString(finalModel, SCHEMA_LIMITS.MODEL_USED_MAX, GOD_CORE_MODEL),
            createdAt: serverTimestamp(),
          });

          await updateDoc(doc(db, 'users', uid, 'conversations', convId), {
            title: sanitizeBoundedString(currentTitle, SCHEMA_LIMITS.CONVERSATION_TITLE_MAX, 'Thread'),
            lastIntent: finalIntent,
            lastMessagePreview: sanitizeBoundedString(cleanedOutput, SCHEMA_LIMITS.MESSAGE_PREVIEW_MAX, ''),
            messageCount: currentMessageCount + 1,
            updatedAt: serverTimestamp(),
          });
        } catch (err) {
          handleFirestoreError(err, OperationType.WRITE, assistantPath);
        }

        await recordAuditEvent({
          action: 'GOD_CORE_RESPONSE_COMPLETED',
          category: 'chat',
          severity: 'info',
          summary: `Classified [${finalIntent}] and streamed response via ${finalModel}.`,
        });
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') {
          setChatError('Active stream aborted.');
        } else {
          setChatError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        streamAbortRef.current = null;
        setIsStreamingChat(false);
        setStreamingText('');
        setStreamingMeta(null);
      }
    },
    [
      activeProfile.executionMode,
      activeProfile.emergencyStop,
      firebaseUser,
      activeConversationId,
      cloudConversations,
      cloudMessages,
      recordAuditEvent,
    ]
  );

  const deleteConversation = useCallback(
    async (conversationId: string) => {
      if (!firebaseUser) {
        setPreviewConversations((prev) => prev.filter((c) => c.id !== conversationId));
        setPreviewMessagesMap((prev) => {
          const next = { ...prev };
          delete next[conversationId];
          return next;
        });
        if (activeConversationId === conversationId) {
          setActiveConversationId(null);
        }
        await recordAuditEvent({
          action: 'MEMORY_THREAD_DELETED',
          category: 'memory',
          severity: 'info',
          summary: `Deleted conversation thread ${conversationId} from preview memory.`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const convPath = `users/${uid}/conversations/${conversationId}`;
      try {
        const msgsQuery = query(
          collection(db, 'users', uid, 'conversations', conversationId, 'messages'),
          where('userId', '==', uid)
        );
        const msgSnaps = await getDocs(msgsQuery);

        const batch = writeBatch(db);
        for (const mDoc of msgSnaps.docs) {
          batch.delete(mDoc.ref);
        }
        batch.delete(doc(db, 'users', uid, 'conversations', conversationId));
        await batch.commit();

        if (activeConversationId === conversationId) {
          setActiveConversationId(null);
        }

        await recordAuditEvent({
          action: 'MEMORY_THREAD_DELETED',
          category: 'memory',
          severity: 'info',
          summary: `Deleted conversation thread and ${msgSnaps.size} messages from Cloud Firestore.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, convPath);
      }
    },
    [firebaseUser, activeConversationId, recordAuditEvent]
  );

  const createTask = useCallback(
    async (input: { title: string; category: IntentCategory; priority: TaskPriority }) => {
      const check = validateTaskInput(input.title);
      if (!check.valid) {
        return { ok: false, error: check.error };
      }

      if (!firebaseUser) {
        const now = Date.now();
        const newTask: TaskRecord = {
          id: createSafeId('task'),
          userId: 'preview_operator',
          title: check.sanitizedTitle,
          category: input.category,
          status: 'queued',
          priority: input.priority,
          createdAtMs: now,
          updatedAtMs: now,
        };
        setPreviewTasks((prev) => [newTask, ...prev]);
        await recordAuditEvent({
          action: 'TASK_CREATED',
          category: 'task',
          severity: 'info',
          summary: `Queued task "${check.sanitizedTitle.slice(0, 80)}" [${input.category}].`,
        });
        return { ok: true };
      }

      const uid = firebaseUser.uid;
      const taskId = createSafeId('task');
      const taskPath = `users/${uid}/tasks/${taskId}`;
      try {
        await setDoc(doc(db, 'users', uid, 'tasks', taskId), {
          id: taskId,
          userId: uid,
          title: check.sanitizedTitle,
          category: input.category,
          status: 'queued',
          priority: input.priority,
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'TASK_CREATED',
          category: 'task',
          severity: 'info',
          summary: `Queued task "${check.sanitizedTitle.slice(0, 80)}" [${input.category}].`,
        });
        return { ok: true };
      } catch (err) {
        handleFirestoreError(err, OperationType.CREATE, taskPath);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const updateTaskStatus = useCallback(
    async (taskId: string, status: TaskStatus) => {
      if (!firebaseUser) {
        setPreviewTasks((prev) =>
          prev.map((t) =>
            t.id === taskId && t.status !== 'archived'
              ? { ...t, status, updatedAtMs: Date.now() }
              : t
          )
        );
        await recordAuditEvent({
          action: 'TASK_STATUS_UPDATED',
          category: 'task',
          severity: 'info',
          summary: `Updated task ${taskId} status to ${status}.`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const taskPath = `users/${uid}/tasks/${taskId}`;
      try {
        await updateDoc(doc(db, 'users', uid, 'tasks', taskId), {
          status,
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'TASK_STATUS_UPDATED',
          category: 'task',
          severity: 'info',
          summary: `Transitioned task ${taskId} to ${status}.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, taskPath);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const deleteTask = useCallback(
    async (taskId: string) => {
      if (!firebaseUser) {
        setPreviewTasks((prev) => prev.filter((t) => t.id !== taskId));
        await recordAuditEvent({
          action: 'TASK_DELETED',
          category: 'memory',
          severity: 'info',
          summary: `Removed task record ${taskId}.`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const taskPath = `users/${uid}/tasks/${taskId}`;
      try {
        await deleteDoc(doc(db, 'users', uid, 'tasks', taskId));
        await recordAuditEvent({
          action: 'TASK_DELETED',
          category: 'memory',
          severity: 'info',
          summary: `Deleted task record ${taskId} from Cloud Firestore.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.DELETE, taskPath);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const setExecutionMode = useCallback(
    async (mode: ExecutionMode) => {
      if (!firebaseUser) {
        setPreviewProfile((prev) => ({ ...prev, executionMode: mode, updatedAtMs: Date.now() }));
        await recordAuditEvent({
          action: 'EXECUTION_MODE_UPDATED',
          category: 'settings',
          severity: mode === 'local' ? 'warning' : 'info',
          summary:
            mode === 'cloud'
              ? 'Execution mode set to Cloud (Gemini).'
              : `Execution mode configured to ${mode.toUpperCase()} (0 local nodes paired; local execution disabled).`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const userPath = `users/${uid}`;
      try {
        await updateDoc(doc(db, 'users', uid), {
          executionMode: mode,
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'EXECUTION_MODE_UPDATED',
          category: 'settings',
          severity: mode === 'local' ? 'warning' : 'info',
          summary:
            mode === 'cloud'
              ? 'Execution mode set to Cloud (Gemini).'
              : `Execution mode configured to ${mode.toUpperCase()} (0 local nodes paired; local execution disabled).`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, userPath);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const toggleEmergencyStop = useCallback(
    async (engaged: boolean) => {
      if (engaged) {
        abortActiveStream();
      }

      if (!firebaseUser) {
        setPreviewProfile((prev) => ({ ...prev, emergencyStop: engaged, updatedAtMs: Date.now() }));
        await recordAuditEvent({
          action: engaged ? 'EMERGENCY_STOP_ENGAGED' : 'EMERGENCY_STOP_RELEASED',
          category: 'security',
          severity: engaged ? 'critical' : 'info',
          summary: engaged
            ? 'Operator engaged Emergency Stop kill-switch. Active streams and tool dispatches halted.'
            : 'Operator released Emergency Stop kill-switch. Normal GOD Core routing restored.',
        });
        return;
      }

      const uid = firebaseUser.uid;
      const userPath = `users/${uid}`;
      try {
        await updateDoc(doc(db, 'users', uid), {
          emergencyStop: engaged,
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: engaged ? 'EMERGENCY_STOP_ENGAGED' : 'EMERGENCY_STOP_RELEASED',
          category: 'security',
          severity: engaged ? 'critical' : 'info',
          summary: engaged
            ? 'Operator engaged Emergency Stop kill-switch. Active streams and tool dispatches halted.'
            : 'Operator released Emergency Stop kill-switch. Normal GOD Core routing restored.',
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, userPath);
      }
    },
    [firebaseUser, abortActiveStream, recordAuditEvent]
  );

  const updateCapabilityPermission = useCallback(
    async (key: CapabilityPermissionKey, enabled: boolean) => {
      if (!firebaseUser) {
        setPreviewProfile((prev) => ({ ...prev, [key]: enabled, updatedAtMs: Date.now() }));
        await recordAuditEvent({
          action: 'CAPABILITY_APPROVAL_CHANGED',
          category: 'security',
          severity: enabled ? 'warning' : 'info',
          summary: `Set ${key} approval gate to ${enabled ? 'APPROVED' : 'LOCKED'}.`,
        });
        return;
      }

      const uid = firebaseUser.uid;
      const userPath = `users/${uid}`;
      try {
        await updateDoc(doc(db, 'users', uid), {
          [key]: enabled,
          updatedAt: serverTimestamp(),
        });
        await recordAuditEvent({
          action: 'CAPABILITY_APPROVAL_CHANGED',
          category: 'security',
          severity: enabled ? 'warning' : 'info',
          summary: `Set ${key} approval gate to ${enabled ? 'APPROVED' : 'LOCKED'}.`,
        });
      } catch (err) {
        handleFirestoreError(err, OperationType.UPDATE, userPath);
      }
    },
    [firebaseUser, recordAuditEvent]
  );

  const value = useMemo<GodWorkspaceContextValue>(
    () => ({
      authReady,
      firebaseUser,
      isPreviewMode,
      enterPreviewMode,
      exitPreviewMode,
      signInWithGoogle,
      signOutUser,
      authError,
      activeSection,
      setActiveSection,
      profile: activeProfile,
      privateEmail: firebaseUser ? privateEmail : 'preview-local@unauthenticated',
      systemInfo,
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
      tasks,
      createTask,
      updateTaskStatus,
      deleteTask,
      auditEvents,
      bootstrapReadyUid,
      recordAuditEvent,
      setExecutionMode,
      toggleEmergencyStop,
      updateCapabilityPermission,
    }),
    [
      authReady,
      firebaseUser,
      isPreviewMode,
      enterPreviewMode,
      exitPreviewMode,
      signInWithGoogle,
      signOutUser,
      authError,
      activeSection,
      activeProfile,
      privateEmail,
      systemInfo,
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
      tasks,
      createTask,
      updateTaskStatus,
      deleteTask,
      auditEvents,
      bootstrapReadyUid,
      recordAuditEvent,
      setExecutionMode,
      toggleEmergencyStop,
      updateCapabilityPermission,
    ]
  );

  return <GodWorkspaceContext.Provider value={value}>{children}</GodWorkspaceContext.Provider>;
}

export function useGodWorkspace(): GodWorkspaceContextValue {
  const ctx = useContext(GodWorkspaceContext);
  if (!ctx) {
    throw new Error('useGodWorkspace must be used inside GodWorkspaceProvider.');
  }
  return ctx;
}
