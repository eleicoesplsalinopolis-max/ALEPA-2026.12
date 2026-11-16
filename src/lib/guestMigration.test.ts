import { describe, expect, it } from 'vitest';
import {
  runGuestMigration,
  summarizeGuestProgress,
  type GuestMigratableStore,
  type MigrationFirestorePort,
} from './guestMigration';

function createMemoryPort(): {
  port: MigrationFirestorePort;
  collections: Record<string, Record<string, Record<string, unknown>>>;
} {
  const collections: Record<string, Record<string, Record<string, unknown>>> = {
    readingProgress: {},
    simuladoAttempts: {},
    errorNotebook: {},
    topicProgress: {},
    studySessions: {},
  };
  const port: MigrationFirestorePort = {
    async readDoc(subcollection, docId) {
      return collections[subcollection]?.[docId] ?? null;
    },
    async mergeDoc(subcollection, docId, data) {
      if (!collections[subcollection]) collections[subcollection] = {};
      collections[subcollection][docId] = {
        ...(collections[subcollection][docId] || {}),
        ...data,
      };
    },
    serverTime: () => 'SERVER_TS',
  };
  return { port, collections };
}

describe('guestMigration (M2)', () => {
  const sampleStore: GuestMigratableStore = {
    readingProgressMap: {
      mat_1: {
        userId: 'guest_local',
        materialId: 'mat_1',
        materialTitle: 'Apostila Regimento Interno',
        lastPage: 14,
        totalPages: 100,
        progressPercent: 14,
        readingMode: 'book',
        fontSize: 17,
        lineHeight: 1.6,
        maxWidthCh: 68,
        theme: 'paper',
        bookmarks: [{ id: 'bm_1', page: 14, label: 'Art. 10', createdAt: '2026-11-15T10:00:00Z' }],
        highlights: [{ id: 'hl_1', page: 14, quote: 'Trecho importante', color: 'emerald', createdAt: '2026-11-15T10:01:00Z' }],
        annotations: [],
        lastReadAt: '2026-11-15T10:02:00Z',
      },
    },
    simuladoAttempts: [
      {
        id: 'sim_123',
        userId: 'guest_local',
        title: 'Simulado 01',
        mode: 'simulado',
        primaryDisciplineId: 'ns_01_portugues',
        totalQuestions: 10,
        correctCount: 8,
        score: 8,
        durationSeconds: 600,
      },
    ],
    errorNotebook: [
      {
        id: 'err_q1',
        userId: 'guest_local',
        questionId: 'q1',
        disciplineId: 'ns_01_portugues',
        topicTitle: 'Crase',
        questionStem: 'Enunciado',
        correctOption: 'A',
        selectedOption: 'B',
        errorReason: 'atencao',
        improvementNote: 'Revisar regra',
        nextReviewDate: '2026-11-16',
        reviewCount: 0,
        status: 'pending',
      },
    ],
    topicProgressMap: {
      top_1: {
        userId: 'guest_local',
        topicId: 'top_1',
        disciplineId: 'ns_01_portugues',
        theoryDone: true,
        questionsDone: false,
        revisionDone: false,
        masteryLevel: 40,
        notes: 'Nota local',
      },
    },
    studySessions: [
      {
        id: 'ses_1',
        userId: 'guest_local',
        dateKey: '2026-11-15',
        disciplineId: 'ns_01_portugues',
        topicTitle: 'Crase',
        blockType: 'theory',
        durationMinutes: 45,
      },
    ],
  };

  it('summarizes importable guest progress counts accurately', () => {
    const summary = summarizeGuestProgress(sampleStore);
    expect(summary).toEqual({
      readingProgress: 1,
      simuladoAttempts: 1,
      errorNotebook: 1,
      topicProgress: 1,
      studySessions: 1,
      total: 5,
    });
  });

  it('imports with the same IDs and does not duplicate records when triggered twice', async () => {
    const { port, collections } = createMemoryPort();

    const first = await runGuestMigration('uid_abc', sampleStore, port);
    expect(first.total).toBe(5);

    // Triggering migration a second time with the same store must keep exact 1 doc per ID
    await runGuestMigration('uid_abc', sampleStore, port);

    expect(Object.keys(collections.readingProgress)).toEqual(['mat_1']);
    expect(Object.keys(collections.simuladoAttempts)).toEqual(['sim_123']);
    expect(Object.keys(collections.errorNotebook)).toEqual(['err_q1']);
    expect(Object.keys(collections.topicProgress)).toEqual(['top_1']);
    expect(Object.keys(collections.studySessions)).toEqual(['ses_1']);
    expect(collections.simuladoAttempts.sim_123.userId).toBe('uid_abc');
  });
});
