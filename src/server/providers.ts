import { GoogleGenAI, type Content, type GenerateContentResponse } from '@google/genai';
import {
  GOD_CORE_MODEL,
  GOD_CORE_SYSTEM_INSTRUCTION,
} from '../shared/godCoreLogic.ts';
import type { IntentCategory } from '../shared/types.ts';

export interface ChatTurnInput {
  role: 'user' | 'assistant';
  content: string;
}

export interface StreamCompletionInput {
  prompt: string;
  history: ChatTurnInput[];
  classifiedIntent: IntentCategory;
  agentModuleNote: string;
}

export interface IntelligenceProviderAdapter {
  readonly id: string;
  readonly name: string;
  readonly environment: 'cloud' | 'local';
  isAvailable(): boolean;
  streamCompletion(input: StreamCompletionInput): AsyncGenerator<string, void, unknown>;
}

let cachedGenAiClient: GoogleGenAI | null = null;

function getServerGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new Error(
      'GEMINI_API_KEY is not configured on the server. Configure your Gemini API key in Settings > Secrets.'
    );
  }
  if (!cachedGenAiClient) {
    cachedGenAiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return cachedGenAiClient;
}

export class GeminiCloudProviderAdapter implements IntelligenceProviderAdapter {
  public readonly id = 'gemini-cloud';
  public readonly name = 'Google Gemini Cloud';
  public readonly environment = 'cloud' as const;

  public isAvailable(): boolean {
    const key = process.env.GEMINI_API_KEY;
    return Boolean(key && key !== 'MY_GEMINI_API_KEY');
  }

  public async *streamCompletion(
    input: StreamCompletionInput
  ): AsyncGenerator<string, void, unknown> {
    const ai = getServerGeminiClient();

    const contents: Content[] = [];
    for (const turn of input.history.slice(-16)) {
      const trimmed = turn.content.trim();
      if (!trimmed) continue;
      contents.push({
        role: turn.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: trimmed }],
      });
    }
    contents.push({
      role: 'user',
      parts: [{ text: input.prompt }],
    });

    const contextualInstruction = `${GOD_CORE_SYSTEM_INSTRUCTION}

CURRENT REQUEST ROUTING METADATA:
- Classified Intent Domain: ${input.classifiedIntent}
- v0.1 Module Disclosure: ${input.agentModuleNote}`;

    const stream = await ai.models.generateContentStream({
      model: GOD_CORE_MODEL,
      contents,
      config: {
        systemInstruction: contextualInstruction,
      },
    });

    for await (const chunk of stream) {
      const c = chunk as GenerateContentResponse;
      const delta = c.text;
      if (delta) {
        yield delta;
      }
    }
  }
}

/**
 * Provider abstraction stub for future local inference nodes (Ollama / vLLM)
 * connected via authenticated outbound WSS + mTLS relay.
 * Never attempts direct localhost or LAN connections from the cloud backend.
 */
export class OllamaLocalBridgeProviderAdapter implements IntelligenceProviderAdapter {
  public readonly id = 'ollama-local';
  public readonly name = 'Ollama Enrolled Node Bridge';
  public readonly environment = 'local' as const;
  private pairedNodeCount = 0;

  public isAvailable(): boolean {
    return this.pairedNodeCount > 0;
  }

  // eslint-disable-next-line require-yield
  public async *streamCompletion(): AsyncGenerator<string, void, unknown> {
    throw new Error(
      'Local inference unavailable: no Windows or Kali Linux node has completed outbound mTLS enrollment.'
    );
  }
}

export const geminiCloudProvider = new GeminiCloudProviderAdapter();
export const ollamaLocalProvider = new OllamaLocalBridgeProviderAdapter();
