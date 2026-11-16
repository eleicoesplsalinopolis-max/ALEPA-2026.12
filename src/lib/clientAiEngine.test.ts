import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildProfessorPrompt,
  getClientAiKeys,
  getCachedExplanation,
  saveCachedExplanation,
  saveClientAiKeys,
  explainQuestionWithFallback,
} from './clientAiEngine';

class MockStorage implements Storage {
  private store: Record<string, string> = {};
  get length() {
    return Object.keys(this.store).length;
  }
  clear(): void {
    this.store = {};
  }
  getItem(key: string): string | null {
    return Object.prototype.hasOwnProperty.call(this.store, key) ? this.store[key] : null;
  }
  key(index: number): string | null {
    return Object.keys(this.store)[index] || null;
  }
  removeItem(key: string): void {
    delete this.store[key];
  }
  setItem(key: string, value: string): void {
    this.store[key] = String(value);
  }
}

describe('clientAiEngine', () => {
  beforeEach(() => {
    if (typeof globalThis.localStorage === 'undefined') {
      (globalThis as unknown as { localStorage: Storage }).localStorage = new MockStorage();
    } else {
      globalThis.localStorage.clear();
    }
    vi.restoreAllMocks();
  });

  it('builds professor prompt matching CETAP structure', () => {
    const prompt = buildProfessorPrompt({
      questionId: 'q_test_1',
      enunciado: 'Sobre os princípios da administração pública...',
      alternativas: ['Legalidade', 'Impessoalidade', 'Moralidade', 'Publicidade', 'Eficiência'],
      gabarito: 'A',
      respostaAluno: 'B',
      paginaMaterial: 42,
      trechoMaterial: 'Art. 37 da CF/88.',
    });

    expect(prompt).toContain('Professor Especialista na banca CETAP');
    expect(prompt).toContain('Cargo 04 - Assistência Administrativa - Nível Médio - PL.AL.060');
    expect(prompt).toContain('Enunciado: Sobre os princípios da administração pública...');
    expect(prompt).toContain('Gabarito Oficial: Alternativa A');
    expect(prompt).toContain('Resposta do Aluno: Alternativa B');
    expect(prompt).toContain('Trecho do Material (Pág. 42): Art. 37 da CF/88.');
    expect(prompt).toContain("Dica de Ouro da CETAP");
  });

  it('persists and retrieves AI keys in localStorage', () => {
    saveClientAiKeys({
      geminiApiKey: 'gemini-key-123',
      groqApiKey: 'gsk-456',
      openrouterApiKey: 'sk-or-789',
    });

    const keys = getClientAiKeys();
    expect(keys.geminiApiKey).toBe('gemini-key-123');
    expect(keys.groqApiKey).toBe('gsk-456');
    expect(keys.openrouterApiKey).toBe('sk-or-789');
    expect(localStorage.getItem('groq_key')).toBe('gsk-456');
  });

  it('retrieves cached explanation immediately without API call', async () => {
    saveCachedExplanation('q_abc', 'Explicação pré-salva no cache', 'Respondido por Gemini 2.5 Flash');

    const result = await explainQuestionWithFallback({
      questionId: 'q_abc',
      enunciado: 'Enunciado...',
      alternativas: ['A', 'B', 'C', 'D', 'E'],
      gabarito: 'C',
    });

    expect(result.cached).toBe(true);
    expect(result.provider).toBe('cache');
    expect(result.text).toBe('Explicação pré-salva no cache');
    expect(result.providerLabel).toBe('Respondido por Gemini 2.5 Flash');
  });

  it('posts prompt and localStorage keys to /api/explicar-ia on non-cached questions', async () => {
    saveClientAiKeys({
      geminiApiKey: 'test-gemini-key',
      groqApiKey: 'test-groq-key',
      openrouterApiKey: 'test-or-key',
    });

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ texto: 'Explicação gerada pelo servidor', motor: 'Respondido por Groq (Llama 3.3)' }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await explainQuestionWithFallback({
      questionId: 'q_uncached',
      enunciado: 'Questão de teste',
      alternativas: ['A', 'B', 'C', 'D', 'E'],
      gabarito: 'D',
      preferredEngine: 'groq',
    });

    expect(mockFetch).toHaveBeenCalledWith(
      '/api/explicar-ia',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.provedor).toBe('groq');
    expect(callBody.chaves.gemini).toBe('test-gemini-key');
    expect(callBody.chaves.groq).toBe('test-groq-key');
    expect(callBody.chaves.openrouter).toBe('test-or-key');

    expect(result.text).toBe('Explicação gerada pelo servidor');
    expect(result.providerLabel).toBe('Respondido por Groq (Llama 3.3)');
  });
});
