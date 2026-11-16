#!/usr/bin/env npx tsx
import fs from 'node:fs';
import path from 'node:path';
import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';
import {
  extractCleanLinesFromPdfItems,
  runDeterministicQuestionPipeline,
  type ParserPageLine,
  type PdfOutlineTopicSpan,
} from '../server/parser/deterministicQuestionParser';
import type { CampusLevel } from '../src/types';

interface CliArgs {
  input: string;
  out: string;
  quarantine: string;
  dryRun: boolean;
  campus: CampusLevel;
  discipline?: string;
  materialId?: string;
  maxPages?: number;
}

function parseCliArgs(argv: string[]): CliArgs {
  const getArg = (flag: string): string | undefined => {
    const idx = argv.indexOf(flag);
    return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
  };

  const input =
    getArg('--input') ||
    'public/assets/aistudio/assistente_adm_assembleia_legislativa_do_estado_do_para_alepa_2026_basico_questoes_d9b0b488.pdf';
  const out = getArg('--out') || 'parsed_questions.json';
  const quarantine = getArg('--quarantine') || 'quarantine_questions.json';
  const dryRun = argv.includes('--dry-run');
  const campusRaw = getArg('--campus');
  const campus: CampusLevel = campusRaw === 'superior' ? 'superior' : 'medio';
  const discipline = getArg('--discipline');
  const materialId = getArg('--material-id');
  const maxPagesRaw = getArg('--max-pages');
  const maxPages = maxPagesRaw ? Math.max(1, Number(maxPagesRaw)) : undefined;

  return { input, out, quarantine, dryRun, campus, discipline, materialId, maxPages };
}

async function extractOutlineSpans(
  doc: Awaited<ReturnType<typeof pdfjs.getDocument>['promise']>
): Promise<{ spans: PdfOutlineTopicSpan[]; firstContentPage: number }> {
  const outline = await doc.getOutline();
  if (!outline || outline.length === 0) {
    return { spans: [], firstContentPage: 1 };
  }

  async function resolvePage(dest: unknown): Promise<number | null> {
    let resolved = dest;
    if (typeof resolved === 'string') {
      resolved = await doc.getDestination(resolved);
    }
    if (Array.isArray(resolved) && resolved[0]) {
      const idx = await doc.getPageIndex(resolved[0] as never);
      return idx + 1;
    }
    return null;
  }

  const rawTopics: Array<{ disciplineTitle: string; topicTitle: string; startPage: number }> = [];
  for (const d0 of outline) {
    const d0Title = String(d0.title || '').replace(/\s+/g, ' ').trim();
    if (/^como usar esta apostila$/i.test(d0Title)) continue;

    const children = Array.isArray(d0.items) ? d0.items : [];
    if (children.length === 0) {
      const p0 = await resolvePage(d0.dest);
      if (p0 !== null) {
        rawTopics.push({ disciplineTitle: d0Title, topicTitle: d0Title, startPage: p0 });
      }
      continue;
    }

    for (const d1 of children) {
      const p1 = await resolvePage(d1.dest);
      const d1Title = String(d1.title || '').replace(/\s+/g, ' ').trim();
      if (p1 !== null && d1Title) {
        rawTopics.push({
          disciplineTitle: d0Title,
          topicTitle: d1Title,
          startPage: p1,
        });
      }
    }
  }

  rawTopics.sort((a, b) => a.startPage - b.startPage);
  const firstContentPage = rawTopics.length > 0 ? rawTopics[0].startPage : 1;

  const spans: PdfOutlineTopicSpan[] = rawTopics.map((item, idx) => {
    const next = rawTopics[idx + 1];
    const endPage = next ? Math.max(item.startPage, next.startPage - 1) : doc.numPages;
    return {
      disciplineTitle: item.disciplineTitle,
      topicTitle: item.topicTitle,
      startPage: item.startPage,
      endPage,
    };
  });

  return { spans, firstContentPage };
}

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  const resolvedInput = path.resolve(args.input);
  if (!fs.existsSync(resolvedInput)) {
    console.error(`[parseQuestionsPdf] Arquivo não encontrado: ${resolvedInput}`);
    process.exitCode = 1;
    return;
  }

  const fileName = path.basename(resolvedInput);
  const inferredMatId =
    args.materialId ||
    fileName
      .toLowerCase()
      .replace(/\.pdf$/i, '')
      .replace(/_[0-9a-f]{8}$/i, '')
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '');

  console.log(`[parseQuestionsPdf] Lendo PDF: ${fileName} (modo: ${args.dryRun ? 'DRY-RUN' : 'EXPORT-JSON'})`);
  const buffer = fs.readFileSync(resolvedInput);
  const task = pdfjs.getDocument({ data: new Uint8Array(buffer), verbosity: 0 });
  const doc = await task.promise;

  try {
    const { spans, firstContentPage } = await extractOutlineSpans(doc);
    const totalPages = args.maxPages ? Math.min(doc.numPages, args.maxPages) : doc.numPages;
    console.log(
      `[parseQuestionsPdf] Páginas: ${doc.numPages} | Tópicos no sumário: ${spans.length} | Início do conteúdo: pág. ${firstContentPage}`
    );

    const allLines: ParserPageLine[] = [];
    for (let p = firstContentPage; p <= totalPages; p++) {
      const page = await doc.getPage(p);
      const tc = await page.getTextContent();
      const pageLines = extractCleanLinesFromPdfItems(
        tc.items as Array<{ str?: string; hasEOL?: boolean; transform?: number[]; width?: number }>,
        p
      );
      for (const l of pageLines) {
        allLines.push(l);
      }
      page.cleanup();

      if (p % 500 === 0 || p === totalPages) {
        console.log(`[parseQuestionsPdf] Progresso leitura PDF: ${p}/${totalPages} páginas...`);
      }
    }

    const result = runDeterministicQuestionPipeline(allLines, {
      campusLevel: args.campus,
      defaultDisciplineId: args.discipline,
      materialId: inferredMatId,
      materialTitle: fileName.replace(/\.pdf$/i, ''),
      outlineSpans: spans,
    });

    const { report } = result;
    console.log('\n=== RELATÓRIO DE EXTRAÇÃO DETERMINÍSTICA ===');
    console.log(`Arquivo:                     ${fileName}`);
    console.log(`Modo:                        ${args.dryRun ? 'dry-run (sem gravação)' : 'completo'}`);
    console.log(`Total de questões extraídas: ${report.totalQuestionsExtracted}`);
    console.log(`Total de resoluções lidas:    ${report.totalResolutionsExtracted}`);
    console.log(`Total válido (Schema OK):    ${report.totalValid}`);
    console.log(`Total enviado à quarentena:  ${report.totalQuarantined}`);
    console.log(`Violações de schema Rules:   ${report.firestoreSchemaViolations}`);
    console.log(`Tempo de parsing:            ${report.durationMs} ms`);

    if (report.totalQuarantined > 0) {
      console.log('\nMotivos de quarentena:');
      for (const [reason, count] of Object.entries(report.quarantineReasonCounts)) {
        console.log(`  - ${reason}: ${count}`);
      }
      console.log('\nAmostra de itens em quarentena (até 5):');
      for (const q of result.quarantinedQuestions.slice(0, 5)) {
        console.log(
          `  * Q.${q.questionNumber} (pág. ${q.sourcePage}) | motivos=[${q.reasons.join(', ')}] | opções=${q.options.length} | gabarito=${q.correctLetter ?? 'AUSENTE'} | tópico="${q.topicTitle.slice(0, 60)}"`
        );
      }
    }

    if (result.validQuestions.length > 0) {
      const sample = result.validQuestions[0];
      console.log('\nAmostra de questão válida mapeada para Question/Firestore:');
      console.log(
        JSON.stringify(
          {
            id: sample.id,
            disciplineId: sample.disciplineId,
            difficulty: sample.difficulty,
            topicTitle: sample.topicTitle,
            statement: sample.statement.slice(0, 120),
            optionsCount: sample.options.length,
            correctIndex: sample.correctIndex,
            sourcePage: sample.sourcePage,
            escolaridade: sample.escolaridade,
            status: sample.status,
            isPublished: sample.isPublished,
          },
          null,
          2
        )
      );
    }

    if (!args.dryRun) {
      fs.writeFileSync(path.resolve(args.out), JSON.stringify(result.validQuestions, null, 2), 'utf8');
      fs.writeFileSync(
        path.resolve(args.quarantine),
        JSON.stringify(result.quarantinedQuestions, null, 2),
        'utf8'
      );
      console.log(`\n[parseQuestionsPdf] Arquivos gravados: ${args.out} e ${args.quarantine}`);
    }
  } finally {
    await task.destroy();
  }
}

main().catch((err) => {
  console.error('[parseQuestionsPdf] Erro fatal:', err);
  process.exitCode = 1;
});
