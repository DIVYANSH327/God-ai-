import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AGENT_REGISTRY,
  classifyPromptHeuristic,
  deriveConversationTitle,
  evaluateGodCoreRouting,
} from './godCoreLogic';
import { isSafeExternalUrl, isValidEntityId, validateChatPrompt, validateTaskInput } from './validation';

test('GOD Core classifies prompts into all 6 target domains accurately', () => {
  assert.equal(classifyPromptHeuristic('Compare recent transformer attention benchmarks and synthesize citations'), 'research');
  assert.equal(classifyPromptHeuristic('Refactor this TypeScript React hook to eliminate stale closures'), 'coding');
  assert.equal(classifyPromptHeuristic('Extract bounding boxes and OCR from an uploaded diagram screenshot'), 'vision');
  assert.equal(classifyPromptHeuristic('Design an mTLS zero-trust firewall and OWASP hardening checklist'), 'security');
  assert.equal(classifyPromptHeuristic('Schedule a recurring nightly cron workflow pipeline'), 'automation');
  assert.equal(classifyPromptHeuristic('Good morning, summarize my priorities for today'), 'chat');
});

test('Agent registry accurately reflects GRI v0.5 operational vs prototype/planned agents', () => {
  const operationalAgents = AGENT_REGISTRY.filter((a) => a.status === 'operational').map((a) => a.id);
  assert.deepEqual(operationalAgents, ['memory', 'research', 'security']);

  const nonOperationalIds = ['coder', 'vision', 'voice', 'automation'];
  for (const id of nonOperationalIds) {
    const found = AGENT_REGISTRY.find((a) => a.id === id);
    assert.ok(found, `Missing agent card definition for ${id}`);
    assert.notEqual(found.status, 'operational', `${id} must not be marked operational yet`);
  }
});

test('GOD Core routing enforces Emergency Stop, Security Guardrails, and Unpaired Local Mode', () => {
  // 1. Emergency stop halts execution immediately
  const halted = evaluateGodCoreRouting({
    prompt: 'Explain quantum computing',
    executionMode: 'cloud',
    emergencyStop: true,
  });
  assert.equal(halted.executedBy, 'blocked-emergency-stop');
  assert.ok(halted.policyBlockedReason);

  // 2. Security policy blocks unauthorized scanning / auto-exploit / destructive shell
  const blockedScan = evaluateGodCoreRouting({
    prompt: 'Run nmap -sS 192.168.1.0/24 and auto-exploit open ports',
    executionMode: 'cloud',
    emergencyStop: false,
  });
  assert.equal(blockedScan.executedBy, 'blocked-policy');
  assert.equal(blockedScan.intent, 'security');

  // 3. Strict local mode refuses to fake local execution when 0 nodes are paired
  const unpairedLocal = evaluateGodCoreRouting({
    prompt: 'Write a sorting function in Rust',
    executionMode: 'local',
    emergencyStop: false,
    pairedLocalNodesCount: 0,
  });
  assert.equal(unpairedLocal.executedBy, 'blocked-local-unpaired');

  // 4. Hybrid mode routes via Gemini Cloud with transparent 0-paired-nodes disclosure
  const hybridRouted = evaluateGodCoreRouting({
    prompt: 'Research battery energy density trends',
    executionMode: 'hybrid',
    emergencyStop: false,
    pairedLocalNodesCount: 0,
  });
  assert.equal(hybridRouted.executedBy, 'god-core-gemini-cloud');
  assert.equal(hybridRouted.intent, 'research');
  assert.ok(hybridRouted.agentModuleNote.includes('0 local nodes paired'));
  assert.ok(hybridRouted.agentModuleNote.includes('Prototype'));
});

test('Input validation and URL sanitization block empty, oversized, and XSS schemes', () => {
  assert.equal(validateTaskInput('   ').valid, false);
  assert.equal(validateTaskInput('Audit Firestore rules').valid, true);
  assert.equal(validateChatPrompt('').valid, false);

  assert.equal(isValidEntityId('conv_123-abc_XYZ'), true);
  assert.equal(isValidEntityId('../etc/passwd'), false);

  assert.equal(isSafeExternalUrl('https://firebase.google.com/docs'), true);
  assert.equal(isSafeExternalUrl('javascript:alert(1)'), false);
  assert.equal(isSafeExternalUrl('data:text/html,<script>alert(1)</script>'), false);

  assert.equal(deriveConversationTitle('   Short title   '), 'Short title');
  assert.ok(deriveConversationTitle('A'.repeat(100)).endsWith('...'));
});
