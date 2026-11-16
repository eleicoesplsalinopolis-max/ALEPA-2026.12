import type {
  CampusLevel,
  Question,
  QuestionDifficulty,
  QuestionOriginType,
} from '../../src/types';

export interface ParserPageLine {
  text: string;
  pageNumber: number;
}

export interface PdfOutlineTopicSpan {
  disciplineTitle: string;
  topicTitle: string;
  startPage: number;
  endPage: number;
}

export interface PageTextInput {
  pageNumber: number;
  text: string;
  chapterTitle?: string;
  disciplineTitle?: string;
}

export interface RawParsedQuestionBlock {
  questionNumber: number;
  sourcePage: number;
  difficultyLabel: string;
  topicTitle: string;
  statement: string;
  options: string[];
  disciplineHint?: string;
  outlineTopicHint?: string;
}

export interface RawParsedResolutionBlock {
  questionNumber: number;
  sourcePage: number;
  topicTitle: string;
  correctLetter: string;
  explanation: string;
}

export type QuarantineReason =
  | 'empty_topic'
  | 'invalid_options_count'
  | 'short_option'
  | 'missing_answer_key'
  | 'empty_statement'
  | 'statement_exceeds_firestore_limit'
  | 'option_exceeds_firestore_limit'
  | 'empty_explanation';

export interface QuarantinedQuestionRecord {
  questionNumber: number;
  sourcePage: number;
  topicTitle: string;
  difficultyLabel: string;
  statement: string;
  options: string[];
  correctLetter: string | null;
  explanation: string;
  reasons: QuarantineReason[];
}

export interface DeterministicParseReport {
  totalQuestionsExtracted: number;
  totalResolutionsExtracted: number;
  totalValid: number;
  totalQuarantined: number;
  quarantineReasonCounts: Record<string, number>;
  firestoreSchemaViolations: number;
  durationMs: number;
}

export interface DeterministicParseResult {
  validQuestions: Question[];
  quarantinedQuestions: QuarantinedQuestionRecord[];
  report: DeterministicParseReport;
}

export interface DeterministicParseOptions {
  campusLevel?: CampusLevel;
  defaultDisciplineId?: string;
  materialId?: string;
  materialTitle?: string;
  originType?: QuestionOriginType;
  isOfficial?: boolean;
  authorId?: string;
  outlineSpans?: PdfOutlineTopicSpan[];
}

const KNOWN_HYPHEN_PREFIXES = new Set([
  'anti', 'auto', 'bem', 'co', 'contra', 'decreto', 'ex', 'extra', 'guarda',
  'infra', 'inter', 'intra', 'juridico', 'lei', 'macro', 'mal', 'mega', 'micro',
  'mini', 'multi', 'nao', 'político', 'politico', 'porta', 'pos', 'pós', 'pre',
  'pré', 'pro', 'pró', 'pseudo', 'recem', 'recém', 'semi', 'socio', 'sócio',
  'sub', 'super', 'supra', 'tecnico', 'técnico', 'ultra', 'vice',
]);

// Strip invisible chars and control chars (except \n and \t)
export function stripInvisibleChars(raw: string): string {
  return String(raw || '')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF\u00AD]/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

// Remove PDF icon font glyphs and UI navigation artifacts without modifying actual question prose
export function sanitizePdfNoiseLine(rawLine: string): string {
  let line = stripInvisibleChars(rawLine);

  // Preserve leading option tab separator while normalizing trailing/multiple gaps elsewhere
  const tabMatch = line.match(/^([A-E])\t(.*)$/);
  if (tabMatch) {
    return `${tabMatch[1]}\t${sanitizePdfNoiseLine(tabMatch[2]).trim()}`;
  }

  // Strip residual icon tokens emitted by PDF font mapping
  line = line
    .replace(/\bCheck-Circle\b/g, ' ')
    .replace(/\bChevron-right\b/gi, ' ')
    .replace(/\bARROW-LEFT\b/g, ' ')
    .replace(/\bLIST-UL\b/g, ' ')
    .replace(/\bLIGHTBULB\b/g, ' ')
    .replace(/\bBOOKMARK\b/g, ' ')
    .replace(/(?:^|\s)(?:EYE|Check|Times)(?=\s|$)/g, ' ')
    .replace(/[○●](?:\s*[○●])+/g, ' ');

  // Remove interactive footer/navigation prompts
  line = line
    .replace(/Tente resolver antes de conferir/gi, ' ')
    .replace(/VER GABARITO E COMENTÁRIOS/gi, ' ')
    .replace(/Continue de onde parou/gi, ' ')
    .replace(/VOLTAR À QUESTÃO\s*\d*/gi, ' ')
    .replace(/Análise Detalhada das Alternativas/gi, ' ')
    .replace(/(?:^|\s)GABARITO(?=\s|$)/g, ' ');

  // Collapse excess whitespace cleanly
  return line.replace(/[ \t]+/g, ' ').trim();
}

export function healWrappedLines(lines: string[]): string {
  if (lines.length === 0) return '';
  let result = '';

  for (const raw of lines) {
    const chunk = raw.trim();
    if (!chunk) continue;

    if (!result) {
      result = chunk;
      continue;
    }

    // Heal soft PDF end-of-line hyphenation when word continues in lowercase
    const hyphenMatch = result.match(/([A-Za-zÀ-ÿ]{2,})-$/);
    if (hyphenMatch && /^[a-zà-ÿ]/.test(chunk)) {
      const prefixNorm = hyphenMatch[1]
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '');
      if (KNOWN_HYPHEN_PREFIXES.has(prefixNorm)) {
        result = `${result}${chunk}`;
      } else {
        result = `${result.slice(0, -1)}${chunk}`;
      }
    } else {
      result = `${result} ${chunk}`;
    }
  }

  return result.replace(/\s+/g, ' ').trim();
}

export function normalizeDifficulty(label: string): QuestionDifficulty {
  const norm = label
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();
  if (norm.includes('dificil') || norm.includes('avancad')) return 'avancado';
  if (norm.includes('medio') || norm.includes('intermediar')) return 'intermediario';
  return 'basico';
}

export function mapSectionToDisciplineId(
  sectionTitle: string | undefined,
  campusLevel: CampusLevel,
  fallbackId?: string
): string {
  const s = (sectionTitle || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');

  if (campusLevel === 'medio') {
    if (s.includes('secretaria')) return 'nm_04_secretaria';
    if (s.includes('portugues')) return 'nm_portugues';
    if (s.includes('informatica')) return 'nm_informatica';
    if (s.includes('raciocinio logico')) return 'nm_raciocinio_logico';
    if (s.includes('direito administrativo')) return 'nm_01_04_administrativo';
    if (s.includes('administracao publica')) return 'nm_04_administracao_publica';
    if (s.includes('direito constitucional')) return 'nm_01_04_constitucional';
    if (s.includes('arquivologia')) return 'nm_04_arquivologia';
    if (s.includes('recursos materiais')) return 'nm_04_recursos_materiais';
    if (s.includes('tecnica legislativa')) return 'nm_01_04_tecnica_legislativa';
    if (s.includes('etica') || s.includes('legislacao')) return 'nm_legislacao_etica';
    return fallbackId || 'nm_portugues';
  }

  if (s.includes('portugues')) return 'portugues';
  if (s.includes('informatica')) return 'informatica';
  if (s.includes('raciocinio logico')) return 'raciocinio_logico';
  if (s.includes('direito administrativo')) return 'direito_administrativo';
  if (s.includes('administracao publica') || s.includes('recursos materiais')) return 'administracao_gestao';
  if (s.includes('direito constitucional')) return 'direito_constitucional';
  if (s.includes('tecnica legislativa') || s.includes('processo legislativo')) return 'processo_legislativo';
  if (s.includes('etica') || s.includes('legislacao')) return 'legislacao_etica';
  if (s.includes('arquivologia') || s.includes('secretaria')) return 'juridicas_complementares';
  return fallbackId || 'portugues';
}

/**
 * Reconstructs clean per-page lines from pdfjs `getTextContent().items`.
 * Strips running headers (y >= 740) and page footers (y <= 68 matching "N / Total"),
 * and preserves wide horizontal gaps after single option letters A..E as `\t`
 * so normal prose starting with "A Constituição..." is never confused with Alternative A.
 */
export function extractCleanLinesFromPdfItems(
  items: Array<{ str?: string; hasEOL?: boolean; transform?: number[]; width?: number }>,
  pageNumber: number
): ParserPageLine[] {
  const lines: string[] = [];
  let current = '';
  let prevY: number | null = null;
  let prevEndX: number | null = null;

  const flushLine = () => {
    if (!current) return;
    const cleaned = sanitizePdfNoiseLine(current);
    if (cleaned && !/^\d+\s*\/\s*\d+$/.test(cleaned)) {
      lines.push(cleaned);
    }
    current = '';
  };

  for (const it of items) {
    if (typeof it.str !== 'string') continue;
    const y = Array.isArray(it.transform) ? it.transform[5] : undefined;
    const x = Array.isArray(it.transform) ? it.transform[4] : undefined;
    const width = typeof it.width === 'number' ? it.width : 0;

    // Filter out running header and page number footer
    if (typeof y === 'number') {
      if (y >= 740) continue;
      if (y <= 68 && /^\s*\d+\s*\/\s*\d+\s*$/.test(it.str)) continue;
    }

    if (typeof y === 'number' && prevY !== null && Math.abs(y - prevY) > 2.5) {
      flushLine();
      prevEndX = null;
    }

    const rawStr = stripInvisibleChars(it.str);
    if (!current) {
      const trimmedLeft = rawStr.trimStart();
      if (trimmedLeft) {
        current = trimmedLeft;
      }
    } else if (/^[A-E]$/.test(current) && rawStr.trim() === '' && width >= 8) {
      // Wide gap after isolated alternative letter badge (e.g. "A   texto...")
      current = `${current}\t`;
    } else if (/^[A-E]$/.test(current) && typeof x === 'number' && prevEndX !== null && x - prevEndX >= 8) {
      current = `${current}\t${rawStr.trimStart()}`;
    } else if (!current.endsWith('\t') && !current.endsWith(' ') && rawStr.trim() && typeof x === 'number' && prevEndX !== null && x - prevEndX > 1.5 && !rawStr.startsWith(' ')) {
      current += ` ${rawStr}`;
    } else {
      current += rawStr;
    }

    if (typeof y === 'number') prevY = y;
    if (typeof x === 'number') prevEndX = x + width;

    if (it.hasEOL) {
      flushLine();
      prevY = null;
      prevEndX = null;
    }
  }
  flushLine();

  return lines.map((text) => ({ text, pageNumber }));
}

export function buildLinesFromPageTextInputs(pages: PageTextInput[]): ParserPageLine[] {
  const out: ParserPageLine[] = [];
  for (const page of pages) {
    const rawLines = stripInvisibleChars(page.text || '').split(/\r?\n/);
    for (const rawLine of rawLines) {
      // Preserve explicit double-space / tab after leading A-E option markers before sanitizing
      const optMarker = rawLine.match(/^\s*([A-E])(?:\t|\s{2,})(.+)$/);
      if (optMarker) {
        const cleanedBody = sanitizePdfNoiseLine(optMarker[2]);
        if (cleanedBody) {
          out.push({ text: `${optMarker[1]}\t${cleanedBody}`, pageNumber: page.pageNumber });
        }
        continue;
      }

      const cleaned = sanitizePdfNoiseLine(rawLine);
      if (!cleaned) continue;
      if (/^\d+\s*\/\s*\d+$/.test(cleaned)) continue;
      // Skip running header if present in raw text
      if (/^\d+\.\s+.+\s+\d+\.\d+\./.test(cleaned)) continue;
      out.push({ text: cleaned, pageNumber: page.pageNumber });
    }
  }
  return out;
}

const OPTION_LETTERS = ['A', 'B', 'C', 'D', 'E'] as const;

function matchOptionStart(line: string, expectedNextIndex: number): { letter: string; body: string } | null {
  // 1. Tab-delimited from PDF item spacing or explicit >=2 spaces: "A\tTexto" or "A  Texto"
  let m = line.match(/^([A-E])(?:\t|\s{2,})(.+)$/);
  if (!m) {
    // 2. Explicit punctuation delimiter: "A) Texto", "(A) Texto", "A. Texto", "A - Texto"
    m = line.match(/^\(?([A-E])[).:\-]\s+(.+)$/);
  }
  if (!m) {
    // 3. Fallback single-space only when matching exact next sequential option letter (B after A, C after B, etc.)
    // Note: intentionally NOT matching single-space 'A ' when expectedNextIndex === 0 to avoid "A Constituição..."!
    if (expectedNextIndex > 0) {
      const single = line.match(/^([B-E])\s+(.+)$/);
      if (single && OPTION_LETTERS.indexOf(single[1] as (typeof OPTION_LETTERS)[number]) === expectedNextIndex) {
        m = single;
      }
    }
  }
  if (!m) return null;
  const letter = m[1].toUpperCase();
  const body = m[2].trim();
  const idx = OPTION_LETTERS.indexOf(letter as (typeof OPTION_LETTERS)[number]);
  if (idx === -1) return null;
  // Require strictly progressive order (allowing skipped letters only if >= expectedNextIndex)
  if (idx < expectedNextIndex) return null;
  return { letter, body };
}

function isSectionHeadingLine(line: string): boolean {
  return (
    /^\d+\.\d+(?:\.\d+)?\s+(?:Questões|Gabaritos|[A-ZÀ-Ú])/.test(line) ||
    /^\d+\s*[A-ZÀ-Ú]{4,}/.test(line) ||
    /^SUMÁRIO\b/i.test(line)
  );
}

function isDifficultyBadgeLine(line: string): string | null {
  const m = line.match(/^(FÁCIL|MÉDIO|DIFÍCIL|FACIL|MEDIO|DIFICIL)$/i);
  return m ? m[1].toUpperCase() : null;
}

function resolveOutlineContext(
  pageNumber: number,
  spans: PdfOutlineTopicSpan[] | undefined
): PdfOutlineTopicSpan | undefined {
  if (!spans || spans.length === 0) return undefined;
  return spans.find((s) => pageNumber >= s.startPage && pageNumber <= s.endPage);
}

function looksAllCapsTopic(line: string): boolean {
  if (line.length < 4 || line.length > 180) return false;
  if (/^(Questão|Resolução|A alternativa|SUMÁRIO)/i.test(line)) return false;
  if (isDifficultyBadgeLine(line)) return false;
  const letters = line.replace(/[^A-Za-zÀ-ÿ]/g, '');
  if (letters.length < 4) return false;
  const upperCount = (letters.match(/[A-ZÀ-Ý]/g) || []).length;
  return upperCount / letters.length >= 0.85;
}

function cleanCommentaryBody(lines: string[]): string {
  const cleanedLines: string[] = [];
  for (const raw of lines) {
    // Format breakdown items neatly e.g. "(A) Incorreta. ..." as separate concise bullets/sentences
    if (/^\([A-E]\)\s*/.test(raw)) {
      cleanedLines.push(`\n${raw}`);
    } else {
      cleanedLines.push(raw);
    }
  }
  // Join non-bullet continuation lines smoothly while keeping bullet breaks
  const paragraphs = cleanedLines
    .join('\n')
    .split(/\n+/)
    .map((p) => p.trim())
    .filter(Boolean);

  // Merge lines inside paragraphs (handling PDF hyphenation wraps)
  const mergedParagraphs: string[] = [];
  let buf: string[] = [];
  for (const p of paragraphs) {
    if (/^\([A-E]\)/.test(p)) {
      if (buf.length > 0) {
        mergedParagraphs.push(healWrappedLines(buf));
        buf = [];
      }
      buf.push(p);
    } else {
      buf.push(p);
    }
  }
  if (buf.length > 0) {
    mergedParagraphs.push(healWrappedLines(buf));
  }

  return mergedParagraphs.join(' ').replace(/\s+/g, ' ').trim();
}

export function extractRawQuestionsAndResolutions(
  lines: ParserPageLine[],
  outlineSpans?: PdfOutlineTopicSpan[]
): {
  questions: RawParsedQuestionBlock[];
  resolutions: RawParsedResolutionBlock[];
} {
  const questions: RawParsedQuestionBlock[] = [];
  const resolutions: RawParsedResolutionBlock[] = [];

  type Mode = 'none' | 'question' | 'resolution';
  let mode: Mode = 'none';

  // Active question state
  let qNum = 0;
  let qPage = 1;
  let qDiff = '';
  let qTopic = '';
  let qHeaderDone = false;
  let qStatementLines: string[] = [];
  let qOptionsLines: string[][] = [];
  let currentOptionIdx = -1;

  // Active resolution state
  let rNum = 0;
  let rPage = 1;
  let rTopic = '';
  let rLetter = '';
  let rHeaderDone = false;
  let rBodyLines: string[] = [];

  const flushActive = () => {
    if (mode === 'question' && qNum > 0) {
      const span = resolveOutlineContext(qPage, outlineSpans);
      let resolvedTopic = qTopic
        .replace(/\s*(?:[○●]\s*)*(?:FÁCIL|MÉDIO|DIFÍCIL|FACIL|MEDIO|DIFICIL)\s*$/i, '')
        .trim();
      // Preserve empty topic if card literally omitted it (quarantine test),
      // only expand truncated "…"-suffixed card banners from outline topic.
      if (resolvedTopic && resolvedTopic.endsWith('…') && span?.topicTitle) {
        resolvedTopic = span.topicTitle;
      }
      questions.push({
        questionNumber: qNum,
        sourcePage: qPage,
        difficultyLabel: qDiff || 'FÁCIL',
        topicTitle: resolvedTopic,
        statement: healWrappedLines(qStatementLines),
        options: qOptionsLines.map((optLines) => healWrappedLines(optLines)),
        disciplineHint: span?.disciplineTitle,
        outlineTopicHint: span?.topicTitle,
      });
    } else if (mode === 'resolution' && rNum > 0) {
      resolutions.push({
        questionNumber: rNum,
        sourcePage: rPage,
        topicTitle: rTopic.trim(),
        correctLetter: rLetter,
        explanation: cleanCommentaryBody(rBodyLines),
      });
    }
    mode = 'none';
  };

  for (let i = 0; i < lines.length; i++) {
    const { text, pageNumber } = lines[i];

    // Check for standalone badge number directly preceding Questão N / Resolução da Questão N
    if (/^\d{1,5}$/.test(text) && i + 1 < lines.length) {
      const next = lines[i + 1].text;
      if (/^(?:Questão|Resolução da Questão)\s+\d+\b/i.test(next)) {
        continue;
      }
    }

    const qMatch = text.match(/^(?:\d+\s+)?Questão\s+(\d+)\b(.*)$/i);
    if (qMatch) {
      flushActive();
      mode = 'question';
      qNum = Number(qMatch[1]);
      qPage = pageNumber;
      qDiff = '';
      qTopic = '';
      qHeaderDone = false;
      qStatementLines = [];
      qOptionsLines = [];
      currentOptionIdx = -1;

      const trailing = qMatch[2].trim();
      if (trailing) {
        const diffInline = trailing.match(/\b(FÁCIL|MÉDIO|DIFÍCIL|FACIL|MEDIO|DIFICIL)\b/i);
        if (diffInline) {
          qDiff = diffInline[1].toUpperCase();
        }
        const cleanedTrail = trailing
          .replace(/\b(FÁCIL|MÉDIO|DIFÍCIL|FACIL|MEDIO|DIFICIL)\b/gi, '')
          .trim();
        if (cleanedTrail && looksAllCapsTopic(cleanedTrail)) {
          qTopic = cleanedTrail;
        }
      }
      continue;
    }

    const rMatch = text.match(/^(?:\d+\s+)?Resolução da Questão\s+(\d+)\b(.*)$/i);
    if (rMatch) {
      flushActive();
      mode = 'resolution';
      rNum = Number(rMatch[1]);
      rPage = pageNumber;
      rTopic = '';
      rLetter = '';
      rHeaderDone = false;
      rBodyLines = [];

      const trailing = rMatch[2].trim();
      if (trailing && looksAllCapsTopic(trailing)) {
        rTopic = trailing;
      }
      continue;
    }

    if (mode === 'none') continue;

    // Stop active block on new syllabus section heading
    if (isSectionHeadingLine(text)) {
      flushActive();
      continue;
    }

    if (mode === 'question') {
      if (!qHeaderDone) {
        const diffBadge = isDifficultyBadgeLine(text);
        if (diffBadge) {
          qDiff = diffBadge;
          continue;
        }
        // Check if difficulty badge is appended to topic line, e.g. "PREPARO... FÁCIL"
        const topicWithDiff = text.match(/^(.*?)\s+(FÁCIL|MÉDIO|DIFÍCIL|FACIL|MEDIO|DIFICIL)$/i);
        if (topicWithDiff && looksAllCapsTopic(topicWithDiff[1])) {
          qTopic = qTopic ? `${qTopic} ${topicWithDiff[1].trim()}` : topicWithDiff[1].trim();
          qDiff = topicWithDiff[2].toUpperCase();
          continue;
        }
        if (!qTopic && looksAllCapsTopic(text)) {
          qTopic = text;
          continue;
        }
        // Wrapped second line of topic banner (never append standalone difficulty words)
        if (
          qTopic &&
          qStatementLines.length === 0 &&
          currentOptionIdx === -1 &&
          !isDifficultyBadgeLine(text) &&
          (looksAllCapsTopic(text) || /^…$/.test(text))
        ) {
          qTopic = `${qTopic} ${text}`.trim();
          continue;
        }
        qHeaderDone = true;
      }

      const expectedNext = qOptionsLines.length;
      const optMatch = matchOptionStart(text, expectedNext);
      if (optMatch) {
        qOptionsLines.push([optMatch.body]);
        currentOptionIdx = qOptionsLines.length - 1;
        continue;
      }

      if (currentOptionIdx >= 0) {
        qOptionsLines[currentOptionIdx].push(text);
      } else {
        qStatementLines.push(text);
      }
    } else if (mode === 'resolution') {
      if (!rHeaderDone) {
        if (!rTopic && looksAllCapsTopic(text)) {
          rTopic = text;
          continue;
        }
        if (rTopic && !rLetter && rBodyLines.length === 0 && (looksAllCapsTopic(text) || /^…$/.test(text))) {
          rTopic = `${rTopic} ${text}`.trim();
          continue;
        }
        rHeaderDone = true;
      }

      const ansMatch = text.match(/^A alternativa correta é a\s+(?:letra\s+)?([A-E])\b[.:]?\s*(.*)$/i);
      if (ansMatch && !rLetter) {
        rLetter = ansMatch[1].toUpperCase();
        if (ansMatch[2] && ansMatch[2].trim()) {
          rBodyLines.push(ansMatch[2].trim());
        }
        continue;
      }

      // Handle case where "A alternativa correta é a" and "B" ended up on consecutive lines
      if (/^A alternativa correta é a$/i.test(text) && !rLetter && i + 1 < lines.length) {
        const nextLine = lines[i + 1].text.trim();
        if (/^[A-E]$/i.test(nextLine)) {
          rLetter = nextLine.toUpperCase();
          i += 1;
          continue;
        }
      }

      rBodyLines.push(text);
    }
  }

  flushActive();
  return { questions, resolutions };
}

function truncateAtBoundary(text: string, maxLen: number): string {
  const s = text.trim();
  if (s.length <= maxLen) return s;
  const slice = s.slice(0, maxLen - 1);
  const lastDot = slice.lastIndexOf('.');
  if (lastDot >= maxLen * 0.6) {
    return slice.slice(0, lastDot + 1).trim();
  }
  const lastSpace = slice.lastIndexOf(' ');
  if (lastSpace >= maxLen * 0.6) {
    return `${slice.slice(0, lastSpace).trim()}…`;
  }
  return `${slice.trim()}…`;
}

export function isFirestoreCompatibleQuestion(q: Question): string[] {
  const errs: string[] = [];
  if (!q.id || !/^[a-zA-Z0-9_-]{1,128}$/.test(q.id)) errs.push('invalid_id');
  if (!q.disciplineId || q.disciplineId.length < 1 || q.disciplineId.length > 80) errs.push('invalid_disciplineId');
  if (!q.topicTitle || q.topicTitle.length < 1 || q.topicTitle.length > 200) errs.push('invalid_topicTitle');
  if (!q.statement || q.statement.length < 5 || q.statement.length > 2500) errs.push('invalid_statement');
  if (!Array.isArray(q.options) || q.options.length !== 5) {
    errs.push('invalid_options_length');
  } else if (q.options.some((o) => typeof o !== 'string' || o.length < 1 || o.length > 500)) {
    errs.push('invalid_option_length');
  }
  if (!Number.isInteger(q.correctIndex) || q.correctIndex < 0 || q.correctIndex > 4) {
    errs.push('invalid_correctIndex');
  }
  if (!q.explanation || q.explanation.length < 1 || q.explanation.length > 2000) {
    errs.push('invalid_explanation');
  }
  if (q.source && q.source.length > 160) errs.push('invalid_source');
  if (q.sourcePage !== undefined && (!Number.isInteger(q.sourcePage) || q.sourcePage < 1 || q.sourcePage > 20000)) {
    errs.push('invalid_sourcePage');
  }
  return errs;
}

export function runDeterministicQuestionPipeline(
  lines: ParserPageLine[],
  options: DeterministicParseOptions = {}
): DeterministicParseResult {
  const startedAt = Date.now();
  const campusLevel: CampusLevel = options.campusLevel ?? 'medio';
  const originType: QuestionOriginType = options.originType ?? 'training_platform';
  const isOfficial = options.isOfficial ?? false;
  const authorId = options.authorId ?? 'system_deterministic_parser';

  const { questions, resolutions } = extractRawQuestionsAndResolutions(lines, options.outlineSpans);

  // Index resolutions by questionNumber (list per number in case a book restarts numbering)
  const resolutionsByNum = new Map<number, RawParsedResolutionBlock[]>();
  for (const res of resolutions) {
    const bucket = resolutionsByNum.get(res.questionNumber);
    if (bucket) bucket.push(res);
    else resolutionsByNum.set(res.questionNumber, [res]);
  }

  const validQuestions: Question[] = [];
  const quarantinedQuestions: QuarantinedQuestionRecord[] = [];
  const quarantineReasonCounts: Record<string, number> = {};
  let firestoreSchemaViolations = 0;

  const bumpReason = (reason: string) => {
    quarantineReasonCounts[reason] = (quarantineReasonCounts[reason] || 0) + 1;
  };

  for (const rawQ of questions) {
    const candidates = resolutionsByNum.get(rawQ.questionNumber) || [];
    // Prefer the closest resolution appearing on/after the question's page, otherwise first match
    const matchedRes =
      candidates.find((r) => r.sourcePage >= rawQ.sourcePage) || candidates[0];

    const reasons: QuarantineReason[] = [];
    const topicClean = rawQ.topicTitle.trim();
    if (!topicClean) {
      reasons.push('empty_topic');
    }

    if (rawQ.options.length !== 5) {
      reasons.push('invalid_options_count');
    }

    if (rawQ.options.some((opt) => opt.trim().length < 2)) {
      reasons.push('short_option');
    }

    const correctLetter = matchedRes?.correctLetter?.toUpperCase() || null;
    const correctIndex = correctLetter
      ? OPTION_LETTERS.indexOf(correctLetter as (typeof OPTION_LETTERS)[number])
      : -1;
    if (!matchedRes || correctIndex < 0 || correctIndex > 4) {
      reasons.push('missing_answer_key');
    }

    const statementClean = rawQ.statement.trim();
    if (statementClean.length < 5) {
      reasons.push('empty_statement');
    } else if (statementClean.length > 2500) {
      reasons.push('statement_exceeds_firestore_limit');
    }

    if (rawQ.options.some((opt) => opt.trim().length > 500)) {
      reasons.push('option_exceeds_firestore_limit');
    }

    const rawExplanation = (matchedRes?.explanation || '').trim();
    if (!rawExplanation) {
      reasons.push('empty_explanation');
    }

    if (reasons.length > 0) {
      reasons.forEach(bumpReason);
      quarantinedQuestions.push({
        questionNumber: rawQ.questionNumber,
        sourcePage: rawQ.sourcePage,
        topicTitle: topicClean,
        difficultyLabel: rawQ.difficultyLabel,
        statement: statementClean,
        options: rawQ.options,
        correctLetter,
        explanation: rawExplanation,
        reasons,
      });
      continue;
    }

    const matSlug = (options.materialId || 'pdf_alepa')
      .replace(/[^a-zA-Z0-9_-]+/g, '_')
      .slice(0, 60);
    const id = `${matSlug}_q${String(rawQ.questionNumber).padStart(4, '0')}`;
    const disciplineId = mapSectionToDisciplineId(
      rawQ.disciplineHint,
      campusLevel,
      options.defaultDisciplineId
    );
    const topicTitle = truncateAtBoundary(topicClean, 200);
    const explanation = truncateAtBoundary(rawExplanation, 2000);
    const sourceBase = options.materialTitle
      ? `${options.materialTitle} (Q.${rawQ.questionNumber}, p. ${rawQ.sourcePage})`
      : `Questão ${rawQ.questionNumber} (p. ${rawQ.sourcePage})`;

    const mapped: Question = {
      id,
      authorId,
      disciplineId: disciplineId.slice(0, 80),
      topicTitle,
      statement: statementClean,
      options: [
        rawQ.options[0].trim(),
        rawQ.options[1].trim(),
        rawQ.options[2].trim(),
        rawQ.options[3].trim(),
        rawQ.options[4].trim(),
      ],
      correctIndex,
      explanation,
      source: truncateAtBoundary(sourceBase, 160),
      originType,
      isOfficial,
      difficulty: normalizeDifficulty(rawQ.difficultyLabel),
      questionFormat: 'objetiva',
      escolaridade: campusLevel,
      status: 'in_review',
      isPublished: false,
      sourceMaterialId: options.materialId ? options.materialId.slice(0, 128) : undefined,
      sourcePage: Math.max(1, Math.min(20000, rawQ.sourcePage)),
      sourceExcerpt: truncateAtBoundary(statementClean, 600),
      needsReview: false,
      reviewFlags: [],
    };

    const schemaErrs = isFirestoreCompatibleQuestion(mapped);
    if (schemaErrs.length > 0) {
      firestoreSchemaViolations += 1;
      schemaErrs.forEach(bumpReason);
      quarantinedQuestions.push({
        questionNumber: rawQ.questionNumber,
        sourcePage: rawQ.sourcePage,
        topicTitle: topicClean,
        difficultyLabel: rawQ.difficultyLabel,
        statement: statementClean,
        options: rawQ.options,
        correctLetter,
        explanation: rawExplanation,
        reasons: ['empty_statement'],
      });
      continue;
    }

    validQuestions.push(mapped);
  }

  return {
    validQuestions,
    quarantinedQuestions,
    report: {
      totalQuestionsExtracted: questions.length,
      totalResolutionsExtracted: resolutions.length,
      totalValid: validQuestions.length,
      totalQuarantined: quarantinedQuestions.length,
      quarantineReasonCounts,
      firestoreSchemaViolations,
      durationMs: Date.now() - startedAt,
    },
  };
}
