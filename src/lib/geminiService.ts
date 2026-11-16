import {
  callGeminiDirect,
  callGroqDirect,
  callOpenRouterDirect,
  explainQuestionWithFallback,
  getClientAiKeys,
  saveClientAiKeys,
  getCachedExplanation,
  saveCachedExplanation,
  buildProfessorPrompt,
  type ExplainQuestionInput,
  type ExplainQuestionResult,
  type AiProviderChoice,
} from './clientAiEngine';
import { Question } from '../types';

export {
  callGeminiDirect,
  callGroqDirect,
  callOpenRouterDirect,
  explainQuestionWithFallback,
  getClientAiKeys,
  saveClientAiKeys,
  getCachedExplanation,
  saveCachedExplanation,
  buildProfessorPrompt,
  type ExplainQuestionInput,
  type ExplainQuestionResult,
  type AiProviderChoice,
};

export const explainQuestionClientSide = explainQuestionWithFallback;

export async function generateQuestionsClientSide(params: {
  campus: 'medio' | 'superior';
  disciplineId: string;
  disciplineName: string;
  topicTitle: string;
  subtopics: string[];
  questionCount?: number;
}): Promise<Question[]> {
  const count = params.questionCount || 3;
  const prompt = `Você é um Professor Examinador Especialista na banca CETAP para o concurso da ALEPA (${
    params.campus === 'medio'
      ? 'Cargo 04 - Assistência Administrativa - Nível Médio'
      : 'Cargo 03 - Nível Superior'
  }).
Gere ${count} questões inéditas de múltipla escolha no estilo exato da banca CETAP sobre:
Disciplina: ${params.disciplineName}
Tópico: ${params.topicTitle}
Subtópicos: ${params.subtopics.join(', ') || 'Geral'}

Retorne EXCLUSIVAMENTE um array JSON puro (sem formatação markdown, sem blocos de código \`\`\`json) contendo objetos com o formato:
[
  {
    "id": "q_ai_${Date.now()}_1",
    "statement": "Enunciado claro e contextualizado no estilo CETAP...",
    "options": ["Alternativa A", "Alternativa B", "Alternativa C", "Alternativa D", "Alternativa E"],
    "correctIndex": 0,
    "explanation": "Comentário didático explicando por que a alternativa está correta e apontando o erro das outras.",
    "legalBasis": "CF/88 ou Lei Estadual 5.810/94 (se aplicável)"
  }
]`;

  const keys = getClientAiKeys();
  let rawJson = '';

  if (keys.geminiApiKey) {
    try {
      rawJson = await callGeminiDirect(prompt, keys.geminiApiKey);
    } catch {
      // fallback to groq
    }
  }

  if (!rawJson && keys.groqApiKey) {
    try {
      rawJson = await callGroqDirect(prompt, keys.groqApiKey);
    } catch {
      // fallback to openrouter
    }
  }

  if (!rawJson && keys.openrouterApiKey) {
    try {
      rawJson = await callOpenRouterDirect(prompt, keys.openrouterApiKey);
    } catch {
      // ignore
    }
  }

  if (!rawJson) {
    throw new Error(
      'Nenhuma chave de IA configurada para gerar questões. Clique em "Configurar Chaves de IA" no topo da tela.'
    );
  }

  // Parse JSON cleanly stripping potential code fences
  const cleaned = rawJson
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();

  try {
    const parsed = JSON.parse(cleaned) as Array<{
      id?: string;
      statement: string;
      options: string[];
      correctIndex: number;
      explanation?: string;
      legalBasis?: string;
    }>;

    return parsed.map((item, idx) => ({
      id: item.id || `q_ai_${Date.now()}_${idx}`,
      disciplineId: params.disciplineId,
      topicTitle: params.topicTitle,
      statement: item.statement,
      options: item.options.slice(0, 5) as [string, string, string, string, string],
      correctIndex: typeof item.correctIndex === 'number' ? item.correctIndex : 0,
      explanation: item.explanation || 'Gabarito oficial comentado pelo Professor IA.',
      legalBasis: item.legalBasis || undefined,
      difficulty: 'intermediario',
      originType: 'ai_generated',
      isOfficial: false,
    }));
  } catch {
    throw new Error('A IA não retornou um formato JSON válido de questões. Tente novamente.');
  }
}
