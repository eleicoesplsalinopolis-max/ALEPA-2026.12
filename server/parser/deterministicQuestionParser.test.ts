import { describe, expect, it } from 'vitest';
import {
  buildLinesFromPageTextInputs,
  healWrappedLines,
  isFirestoreCompatibleQuestion,
  runDeterministicQuestionPipeline,
  sanitizePdfNoiseLine,
} from './deterministicQuestionParser';

describe('deterministicQuestionParser', () => {
  it('strips residual PDF icon font artifacts and invisible characters cleanly', () => {
    const dirty = '\u200BLIST-UL Análise \uFEFF Detalhada Check Times ○ ○ ○ Chevron-right B1: 100';
    expect(sanitizePdfNoiseLine(dirty)).toBe('Análise Detalhada B1: 100');
  });

  it('heals soft hyphenated line wraps while preserving known Portuguese prefixes', () => {
    expect(healWrappedLines(['processo de simplifica-', 'ção dos documentos'])).toBe(
      'processo de simplificação dos documentos'
    );
    expect(healWrappedLines(['caráter jurídico-', 'legislativo da norma'])).toBe(
      'caráter jurídico-legislativo da norma'
    );
  });

  it('extracts literal question + A-E options + resolution + sourcePage without LLM rewriting', () => {
    const pages = [
      {
        pageNumber: 12,
        text: [
          '1 Questão 1',
          'PREPARO, PREENCHIMENTO E TRATAMENTO DE DOCUMENTOS',
          '○ ○ ○ FÁCIL',
          'Com a publicação da 3ª edição do Manual de Redação da Presidência da República,',
          'sobre o Padrão Ofício, assinale a alternativa correta:',
          'A  O Padrão Ofício é facultativo.',
          'B  A identificação do órgão foi abolida.',
          'C  Aviso é restrito a comunicações externas.',
          'D  Manteve-se a distinção formal entre Ofício, Aviso e Memorando.',
          'E  O Memorando e o Aviso foram extintos, adotando-se o Padrão Ofício.',
          'LIGHTBULB Tente resolver antes de conferir EYE VER GABARITO E COMENTÁRIOS',
        ].join('\n'),
      },
      {
        pageNumber: 39,
        text: [
          '1 Resolução da Questão 1',
          'PREPARO, PREENCHIMENTO E TRATAMENTO DE DOCUMENTOS',
          'Check-Circle GABARITO',
          'A alternativa correta é a E',
          'A 3ª edição do MRPR unificou os expedientes no Padrão Ofício.',
          'LIST-UL Análise Detalhada das Alternativas',
          'Times (A) Incorreta. É obrigatório.',
          'Check (E) Correta. Descreve com precisão a unificação.',
          'BOOKMARK Continue de onde parou ARROW-LEFT VOLTAR À QUESTÃO 1',
        ].join('\n'),
      },
    ];

    const lines = buildLinesFromPageTextInputs(pages);
    const result = runDeterministicQuestionPipeline(lines, {
      campusLevel: 'medio',
      defaultDisciplineId: 'nm_04_secretaria',
      materialId: 'alepa_basico_questoes',
      materialTitle: 'Apostila Questões Básicas',
    });

    expect(result.report.totalQuestionsExtracted).toBe(1);
    expect(result.report.totalResolutionsExtracted).toBe(1);
    expect(result.report.totalValid).toBe(1);
    expect(result.report.totalQuarantined).toBe(0);
    expect(result.report.firestoreSchemaViolations).toBe(0);

    const q = result.validQuestions[0];
    expect(q.disciplineId).toBe('nm_04_secretaria');
    expect(q.difficulty).toBe('basico');
    expect(q.topicTitle).toBe('PREPARO, PREENCHIMENTO E TRATAMENTO DE DOCUMENTOS');
    expect(q.correctIndex).toBe(4);
    expect(q.sourcePage).toBe(12);
    expect(q.options).toHaveLength(5);
    expect(q.options[4]).toBe('O Memorando e o Aviso foram extintos, adotando-se o Padrão Ofício.');
    expect(q.explanation).not.toContain('LIST-UL');
    expect(q.explanation).not.toContain('Check');
    expect(isFirestoreCompatibleQuestion(q)).toEqual([]);
  });

  it('does not falsely split statement lines beginning with "A Constituição..." as Option A', () => {
    const pages = [
      {
        pageNumber: 15,
        text: [
          '5 Questão 5',
          'PRINCÍPIOS CONSTITUCIONAIS',
          'MÉDIO',
          'A Constituição Federal de 1988 prevê instrumentos de controle.',
          'Assinale a opção correta:',
          'A  Ação Civil Pública.',
          'B  Mandado de Segurança Coletivo.',
          'C  Ação Popular.',
          'D  Mandado de Injunção.',
          'E  Habeas Data.',
        ].join('\n'),
      },
      {
        pageNumber: 45,
        text: [
          '5 Resolução da Questão 5',
          'PRINCÍPIOS CONSTITUCIONAIS',
          'A alternativa correta é a C',
          'Qualquer cidadão pode ajuizar Ação Popular.',
        ].join('\n'),
      },
    ];

    const result = runDeterministicQuestionPipeline(buildLinesFromPageTextInputs(pages), {
      campusLevel: 'superior',
      defaultDisciplineId: 'direito_constitucional',
    });

    expect(result.validQuestions).toHaveLength(1);
    expect(result.validQuestions[0].statement).toContain('A Constituição Federal de 1988');
    expect(result.validQuestions[0].difficulty).toBe('intermediario');
    expect(result.validQuestions[0].correctIndex).toBe(2);
  });

  it('quarantines questions with missing topic, != 5 options, < 2 char option, or missing answer key', () => {
    const pages = [
      {
        pageNumber: 10,
        text: [
          '10 Questão 10',
          'DIFÍCIL',
          'Enunciado sem tópico explícito no cartão:',
          'A  Alternativa um.',
          'B  Alternativa dois.',
          'C  Alternativa três.',
          'D  Alternativa quatro.',
          'E  Alternativa cinco.',
          '11 Questão 11',
          'TÓPICO VÁLIDO',
          'FÁCIL',
          'Questão com apenas quatro alternativas:',
          'A  Primeira.',
          'B  Segunda.',
          'C  Terceira.',
          'D  Quarta.',
          '12 Questão 12',
          'CRASE',
          'FÁCIL',
          'Questão com alternativa excessivamente curta:',
          'A  à',
          'B  ao',
          'C  na',
          'D  da',
          'E  em',
          '13 Questão 13',
          'TÓPICO SEM GABARITO',
          'FÁCIL',
          'Questão sem resolução correspondente no arquivo:',
          'A  Opção A válida.',
          'B  Opção B válida.',
          'C  Opção C válida.',
          'D  Opção D válida.',
          'E  Opção E válida.',
        ].join('\n'),
      },
      {
        pageNumber: 20,
        text: [
          '10 Resolução da Questão 10',
          'A alternativa correta é a A',
          'Comentário Q10.',
          '11 Resolução da Questão 11',
          'A alternativa correta é a B',
          'Comentário Q11.',
          '12 Resolução da Questão 12',
          'A alternativa correta é a A',
          'Comentário Q12.',
        ].join('\n'),
      },
    ];

    const result = runDeterministicQuestionPipeline(buildLinesFromPageTextInputs(pages));
    expect(result.report.totalValid).toBe(0);
    expect(result.report.totalQuarantined).toBe(4);

    const byNum = new Map(result.quarantinedQuestions.map((q) => [q.questionNumber, q.reasons]));
    expect(byNum.get(10)).toContain('empty_topic');
    expect(byNum.get(11)).toContain('invalid_options_count');
    expect(byNum.get(12)).toContain('short_option');
    expect(byNum.get(13)).toContain('missing_answer_key');
  });
});
