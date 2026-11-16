export interface ClientAiKeys {
  geminiApiKey: string;
  groqApiKey: string;
  openrouterApiKey: string;
}

export type AiProviderChoice = 'auto' | 'gemini' | 'groq' | 'openrouter';

export interface ExplainQuestionInput {
  questionId: string;
  enunciado: string;
  alternativas: string[];
  gabarito: string;
  respostaAluno?: string;
  paginaMaterial?: number;
  trechoMaterial?: string;
  preferredEngine?: AiProviderChoice;
}

export interface ExplainQuestionResult {
  text: string;
  provider: 'gemini' | 'groq' | 'openrouter' | 'cache';
  providerLabel: string;
  cached?: boolean;
}

const STORAGE_KEYS = {
  gemini: 'gemini_api_key',
  groq: 'groq_api_key',
  openrouter: 'openrouter_api_key',
} as const;

function getStorage(): Storage | null {
  if (typeof window !== 'undefined' && window.localStorage) return window.localStorage;
  if (typeof globalThis !== 'undefined' && (globalThis as unknown as { localStorage?: Storage }).localStorage) {
    return (globalThis as unknown as { localStorage: Storage }).localStorage;
  }
  return null;
}

export function getClientAiKeys(): ClientAiKeys {
  const storage = getStorage();
  if (!storage) {
    return { geminiApiKey: '', groqApiKey: '', openrouterApiKey: '' };
  }
  try {
    const gemini =
      storage.getItem(STORAGE_KEYS.gemini) ||
      storage.getItem('GEMINI_API_KEY') ||
      (import.meta.env?.VITE_GEMINI_API_KEY as string | undefined) ||
      '';
    const groq =
      storage.getItem(STORAGE_KEYS.groq) ||
      storage.getItem('groq_key') ||
      storage.getItem('GROQ_API_KEY') ||
      '';
    const openrouter =
      storage.getItem(STORAGE_KEYS.openrouter) ||
      storage.getItem('openrouter_key') ||
      storage.getItem('OPENROUTER_API_KEY') ||
      '';
    return {
      geminiApiKey: gemini.trim(),
      groqApiKey: groq.trim(),
      openrouterApiKey: openrouter.trim(),
    };
  } catch {
    return { geminiApiKey: '', groqApiKey: '', openrouterApiKey: '' };
  }
}

export function saveClientAiKeys(keys: {
  geminiApiKey?: string;
  groqApiKey?: string;
  openrouterApiKey?: string;
}): void {
  const storage = getStorage();
  if (!storage) return;
  try {
    if (keys.geminiApiKey !== undefined) {
      const v = keys.geminiApiKey.trim();
      if (v) {
        storage.setItem(STORAGE_KEYS.gemini, v);
      } else {
        storage.removeItem(STORAGE_KEYS.gemini);
      }
    }
    if (keys.groqApiKey !== undefined) {
      const v = keys.groqApiKey.trim();
      if (v) {
        storage.setItem(STORAGE_KEYS.groq, v);
        storage.setItem('groq_key', v);
      } else {
        storage.removeItem(STORAGE_KEYS.groq);
        storage.removeItem('groq_key');
      }
    }
    if (keys.openrouterApiKey !== undefined) {
      const v = keys.openrouterApiKey.trim();
      if (v) {
        storage.setItem(STORAGE_KEYS.openrouter, v);
        storage.setItem('openrouter_key', v);
      } else {
        storage.removeItem(STORAGE_KEYS.openrouter);
        storage.removeItem('openrouter_key');
      }
    }
  } catch {
    // ignore quota errors
  }
}

export function getCachedExplanation(
  questionId: string
): { text: string; providerLabel: string } | null {
  const storage = getStorage();
  if (!storage || !questionId) return null;
  try {
    const raw = storage.getItem(`alepa_ai_expl_${questionId}`);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { text?: string; providerLabel?: string };
    if (typeof parsed?.text === 'string' && parsed.text.trim()) {
      return {
        text: parsed.text.trim(),
        providerLabel: parsed.providerLabel || 'Respondido por Gemini 2.5 Flash',
      };
    }
    return null;
  } catch {
    return null;
  }
}

export function saveCachedExplanation(
  questionId: string,
  text: string,
  providerLabel: string
): void {
  const storage = getStorage();
  if (!storage || !questionId || !text) return;
  try {
    storage.setItem(
      `alepa_ai_expl_${questionId}`,
      JSON.stringify({
        text,
        providerLabel,
        savedAt: Date.now(),
      })
    );
  } catch {
    // ignore quota errors
  }
}

export function buildProfessorPrompt(input: ExplainQuestionInput): string {
  const letters = ['A', 'B', 'C', 'D', 'E'];
  const formattedAlternatives = input.alternativas
    .map((alt, idx) => {
      const prefix = letters[idx] ? `Alternativa ${letters[idx]}: ` : '';
      return `${prefix}${alt.trim()}`;
    })
    .join('\n');

  const gabaritoText = input.gabarito.toUpperCase();
  const respostaAlunoText = input.respostaAluno
    ? input.respostaAluno.toUpperCase()
    : 'Não informada / Em análise';
  const pagina = input.paginaMaterial ? String(input.paginaMaterial) : 'N/D';
  const trecho = input.trechoMaterial
    ? input.trechoMaterial.trim()
    : 'Consulte o livro-base da disciplina no leitor integrado.';

  return `Você é um Professor Especialista na banca CETAP (Cargo 04 - Assistência Administrativa - Nível Médio - PL.AL.060). Explique de forma didática e objetiva a questão abaixo:
Enunciado: ${input.enunciado.trim()}
Alternativas:
${formattedAlternatives}
Gabarito Oficial: Alternativa ${gabaritoText}
Resposta do Aluno: Alternativa ${respostaAlunoText}
Trecho do Material (Pág. ${pagina}): ${trecho}

Regras:
1. Dê um feedback rápido ao aluno (parabenize se acertou ou acolha e mostre a pegadinha se errou).
2. Explique por que a Alternativa ${gabaritoText} é a correta segundo o estilo da banca CETAP.
3. Aponte em tópicos curtos o erro de cada alternativa incorreta.
4. Cite a página ${pagina} e o trecho do material de apoio, se disponível.
5. Encerre com uma 'Dica de Ouro da CETAP' em 2 linhas para o Caderno de Erros.`;
}

async function safeReadJson<T>(res: Response, providerName: string): Promise<T> {
  const rawText = await res.text();
  try {
    return JSON.parse(rawText) as T;
  } catch {
    const preview = rawText.trim().slice(0, 100);
    throw new Error(
      `${providerName}: Resposta inválida (HTTP ${res.status}): ${preview || 'Corpo vazio'}`
    );
  }
}

export async function callGeminiDirect(prompt: string, apiKey: string): Promise<string> {
  const cleanKey = apiKey.trim();
  if (!cleanKey) {
    throw new Error('Chave da API do Google Gemini não configurada.');
  }
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(
    cleanKey
  )}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [
        {
          role: 'user',
          parts: [{ text: prompt }],
        },
      ],
      generationConfig: {
        temperature: 0.3,
      },
    }),
  });

  if (res.status === 429) {
    throw new Error('Limite de cota excedido no Google Gemini (429).');
  }

  if (!res.ok) {
    let msg = `Erro no Gemini (${res.status})`;
    try {
      const errJson = await safeReadJson<{ error?: { message?: string } }>(res, 'Gemini');
      if (errJson?.error?.message) msg = errJson.error.message;
    } catch {
      // ignore
    }
    throw new Error(msg);
  }

  const json = await safeReadJson<{
    candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
  }>(res, 'Gemini');
  const text = json?.candidates?.[0]?.content?.parts?.[0]?.text;
  if (!text || !text.trim()) {
    throw new Error('O Gemini retornou uma resposta em branco.');
  }
  return text.trim();
}

export async function callGroqDirect(prompt: string, apiKey: string): Promise<string> {
  const cleanKey = apiKey.trim();
  if (!cleanKey) {
    throw new Error('Chave da API Groq não configurada.');
  }
  const url = 'https://api.groq.com/openai/v1/chat/completions';

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${cleanKey}`,
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [
        {
          role: 'system',
          content:
            'Você é um Professor Especialista na banca CETAP para concursos públicos da ALEPA.',
        },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
    }),
  });

  if (res.status === 429) {
    throw new Error('Limite de requisições excedido na Groq (429).');
  }

  if (!res.ok) {
    let msg = `Erro na Groq (${res.status})`;
    try {
      const errJson = await safeReadJson<{ error?: { message?: string } }>(res, 'Groq');
      if (errJson?.error?.message) msg = errJson.error.message;
    } catch {
      // ignore
    }
    throw new Error(msg);
  }

  const json = await safeReadJson<{
    choices?: Array<{ message?: { content?: string } }>;
  }>(res, 'Groq');
  const text = json?.choices?.[0]?.message?.content;
  if (!text || !text.trim()) {
    throw new Error('A Groq retornou uma resposta em branco.');
  }
  return text.trim();
}

export async function callOpenRouterDirect(prompt: string, apiKey: string): Promise<string> {
  const cleanKey = apiKey.trim();
  if (!cleanKey) {
    throw new Error('Chave da API OpenRouter não configurada.');
  }
  const url = 'https://openrouter.ai/api/v1/chat/completions';

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${cleanKey}`,
    },
    body: JSON.stringify({
      model: 'meta-llama/llama-3.3-70b-instruct:free',
      messages: [
        {
          role: 'system',
          content:
            'Você é um Professor Especialista na banca CETAP para concursos públicos da ALEPA.',
        },
        { role: 'user', content: prompt },
      ],
      temperature: 0.3,
    }),
  });

  if (res.status === 429) {
    throw new Error('Limite de requisições excedido no OpenRouter (429).');
  }

  if (!res.ok) {
    let msg = `Erro no OpenRouter (${res.status})`;
    try {
      const errJson = await safeReadJson<{ error?: { message?: string } }>(res, 'OpenRouter');
      if (errJson?.error?.message) msg = errJson.error.message;
    } catch {
      // ignore
    }
    throw new Error(msg);
  }

  const json = await safeReadJson<{
    choices?: Array<{ message?: { content?: string } }>;
  }>(res, 'OpenRouter');
  const text = json?.choices?.[0]?.message?.content;
  if (!text || !text.trim()) {
    throw new Error('O OpenRouter retornou uma resposta em branco.');
  }
  return text.trim();
}

export async function explainQuestionWithFallback(
  input: ExplainQuestionInput
): Promise<ExplainQuestionResult> {
  // 1. Check client-side cached explanation in localStorage
  const cached = getCachedExplanation(input.questionId);
  if (cached) {
    return {
      text: cached.text,
      provider: 'cache',
      providerLabel: cached.providerLabel || 'Respondido por Gemini 2.5 Flash',
      cached: true,
    };
  }

  // 1. Leia as chaves salvas no navegador
  const keys = getClientAiKeys();
  const geminiKey = keys.geminiApiKey;
  const groqKey = keys.groqApiKey;
  const openrouterKey = keys.openrouterApiKey;

  const prompt = buildProfessorPrompt(input);
  const preferred = input.preferredEngine || 'auto';

  // 2. Chamar o backend Node.js (/api/explicar-ia) que possui acesso livre para chamar Gemini, Groq e OpenRouter sem bloqueio de sandbox/CORS do iframe
  const res = await fetch('/api/explicar-ia', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      prompt,
      provedor: preferred,
      chaves: {
        gemini: geminiKey,
        groq: groqKey,
        openrouter: openrouterKey,
      },
    }),
  });

  const raw = await res.text();
  let data: { texto?: string; motor?: string; erro?: string } = {};
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error(`Erro do servidor (${res.status}): ${raw.slice(0, 100)}`);
  }

  if (!res.ok || !data.texto) {
    throw new Error(data.erro || `Falha na requisição ao servidor (${res.status}).`);
  }

  const label = data.motor || 'Respondido por Gemini 2.5 Flash';
  saveCachedExplanation(input.questionId, data.texto, label);

  return {
    text: data.texto,
    provider: (preferred as any) || 'gemini',
    providerLabel: label,
  };
}
