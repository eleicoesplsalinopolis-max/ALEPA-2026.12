import {
  doc,
  getDoc,
  serverTimestamp,
  setDoc,
  type Firestore,
} from 'firebase/firestore';
import { mergeById } from './readingMerge';
import type {
  ErrorEntry,
  ReadingProgress,
  SimuladoAttempt,
  StudySession,
  TopicProgress,
} from '../types';

export const GUEST_IMPORTED_FLAG_PREFIX = 'alepa_guest_imported_';

export interface GuestMigratableStore {
  topicProgressMap?: Record<string, TopicProgress>;
  readingProgressMap?: Record<string, ReadingProgress>;
  studySessions?: StudySession[];
  simuladoAttempts?: SimuladoAttempt[];
  errorNotebook?: ErrorEntry[];
}

export interface GuestProgressSummary {
  readingProgress: number;
  simuladoAttempts: number;
  errorNotebook: number;
  topicProgress: number;
  studySessions: number;
  total: number;
}

export function sanitizeMigrationId(raw: string, fallbackPrefix = 'item'): string {
  const cleaned = String(raw || '').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 120);
  return cleaned || `${fallbackPrefix}_${Date.now()}`;
}

export function summarizeGuestProgress(
  store: GuestMigratableStore | null | undefined
): GuestProgressSummary {
  const readingProgress = Object.keys(store?.readingProgressMap || {}).length;
  const simuladoAttempts = Array.isArray(store?.simuladoAttempts) ? store.simuladoAttempts.length : 0;
  const errorNotebook = Array.isArray(store?.errorNotebook) ? store.errorNotebook.length : 0;
  const topicProgress = Object.keys(store?.topicProgressMap || {}).length;
  const studySessions = Array.isArray(store?.studySessions) ? store.studySessions.length : 0;
  const total = readingProgress + simuladoAttempts + errorNotebook + topicProgress + studySessions;
  return {
    readingProgress,
    simuladoAttempts,
    errorNotebook,
    topicProgress,
    studySessions,
    total,
  };
}

export interface MigrationFirestorePort {
  readDoc: (subcollection: string, docId: string) => Promise<Record<string, unknown> | null>;
  mergeDoc: (subcollection: string, docId: string, data: Record<string, unknown>) => Promise<void>;
  serverTime: () => unknown;
}

export function createFirestoreMigrationPort(db: Firestore, uid: string): MigrationFirestorePort {
  return {
    async readDoc(subcollection, docId) {
      const ref = doc(db, 'users', uid, subcollection, docId);
      const snap = await getDoc(ref);
      return snap.exists() ? (snap.data() as Record<string, unknown>) : null;
    },
    async mergeDoc(subcollection, docId, data) {
      const ref = doc(db, 'users', uid, subcollection, docId);
      await setDoc(ref, data, { merge: true });
    },
    serverTime: () => serverTimestamp(),
  };
}

export async function runGuestMigration(
  uid: string,
  store: GuestMigratableStore,
  port: MigrationFirestorePort
): Promise<GuestProgressSummary> {
  const counts: GuestProgressSummary = {
    readingProgress: 0,
    simuladoAttempts: 0,
    errorNotebook: 0,
    topicProgress: 0,
    studySessions: 0,
    total: 0,
  };

  // 1. readingProgress
  for (const [key, item] of Object.entries(store.readingProgressMap || {})) {
    const safeMaterialId = sanitizeMigrationId(item.materialId || key, 'mat');
    const existing = await port.readDoc('readingProgress', safeMaterialId);
    const totalPages = Math.max(1, Math.min(20000, Math.round(item.totalPages || 1)));
    const lastPage = Math.max(1, Math.min(totalPages, Math.round(item.lastPage || 1)));
    const progressPercent = Math.max(
      0,
      Math.min(100, Math.round(item.progressPercent ?? Math.round((lastPage / totalPages) * 100)))
    );
    const readingMode =
      item.readingMode === 'book' || item.readingMode === 'reading' || item.readingMode === 'original'
        ? item.readingMode
        : 'book';
    const fontSize = Math.max(12, Math.min(32, Math.round(item.fontSize || 17)));
    const lineHeight = Math.max(1.1, Math.min(2.6, Number((item.lineHeight || 1.65).toFixed(2))));
    const maxWidthCh = Math.max(40, Math.min(110, Math.round(item.maxWidthCh || 68)));
    const theme =
      item.theme === 'paper' || item.theme === 'sepia' || item.theme === 'night'
        ? item.theme
        : 'paper';
    const materialTitle = (item.materialTitle || 'Documento PDF').trim().slice(0, 200) || 'Documento PDF';
    const lastReadAt = (item.lastReadAt || new Date().toISOString()).slice(0, 40);

    const serverBookmarks = Array.isArray(existing?.bookmarks) ? (existing.bookmarks as ReadingProgress['bookmarks']) : [];
    const serverHighlights = Array.isArray(existing?.highlights) ? (existing.highlights as ReadingProgress['highlights']) : [];
    const serverAnnotations = Array.isArray(existing?.annotations) ? (existing.annotations as ReadingProgress['annotations']) : [];

    const mutablePayload: Record<string, unknown> = {
      materialTitle,
      lastPage: Math.max(lastPage, Number(existing?.lastPage || 1)),
      totalPages: Math.max(totalPages, Number(existing?.totalPages || 1)),
      progressPercent: Math.max(progressPercent, Number(existing?.progressPercent || 0)),
      readingMode,
      fontSize,
      lineHeight,
      maxWidthCh,
      theme,
      bookmarks: mergeById(serverBookmarks, item.bookmarks || [], [], 100),
      highlights: mergeById(serverHighlights, item.highlights || [], [], 150),
      annotations: mergeById(serverAnnotations, item.annotations || [], [], 150),
      lastReadAt,
      updatedAt: port.serverTime(),
    };

    if (existing) {
      await port.mergeDoc('readingProgress', safeMaterialId, mutablePayload);
    } else {
      await port.mergeDoc('readingProgress', safeMaterialId, {
        userId: uid,
        materialId: safeMaterialId,
        ...mutablePayload,
      });
    }
    counts.readingProgress += 1;
  }

  // 2. simuladoAttempts (create-only in firestore.rules -> idempotent check via getDoc)
  for (const attempt of store.simuladoAttempts || []) {
    const safeId = sanitizeMigrationId(attempt.id, 'sim');
    const existing = await port.readDoc('simuladoAttempts', safeId);
    if (!existing) {
      const totalQuestions = Math.max(1, Math.min(200, Math.round(attempt.totalQuestions || 1)));
      const correctCount = Math.max(0, Math.min(totalQuestions, Math.round(attempt.correctCount || 0)));
      await port.mergeDoc('simuladoAttempts', safeId, {
        userId: uid,
        title: (attempt.title || 'Simulado ALEPA').trim().slice(0, 160) || 'Simulado ALEPA',
        mode: attempt.mode === 'treino' ? 'treino' : 'simulado',
        primaryDisciplineId: (attempt.primaryDisciplineId || 'geral').slice(0, 80) || 'geral',
        totalQuestions,
        correctCount,
        score: Math.max(0, Math.min(10, Number((attempt.score || 0).toFixed(2)))),
        durationSeconds: Math.max(0, Math.min(36000, Math.round(attempt.durationSeconds || 0))),
        createdAt: port.serverTime(),
      });
      counts.simuladoAttempts += 1;
    }
  }

  // 3. errorNotebook
  for (const entry of store.errorNotebook || []) {
    const safeQuestionId = sanitizeMigrationId(entry.questionId, 'q');
    const safeId = sanitizeMigrationId(entry.id || `err_${safeQuestionId}`, 'err');
    const existing = await port.readDoc('errorNotebook', safeId);
    const errorReason =
      entry.errorReason === 'atencao' ||
      entry.errorReason === 'teoria' ||
      entry.errorReason === 'lei_seca' ||
      entry.errorReason === 'banca_cetap'
        ? entry.errorReason
        : 'teoria';
    const nextReviewDate = (entry.nextReviewDate || new Date().toISOString().slice(0, 10)).slice(0, 20);
    const reviewCount = Math.max(0, Math.min(1000, Math.round(entry.reviewCount || 0)));
    const status = entry.status === 'mastered' ? 'mastered' : 'pending';

    if (existing) {
      await port.mergeDoc('errorNotebook', safeId, {
        errorReason,
        improvementNote: (entry.improvementNote || '').slice(0, 2000),
        nextReviewDate,
        reviewCount: Math.max(reviewCount, Number(existing.reviewCount || 0)),
        status: existing.status === 'mastered' ? 'pending' : status,
        updatedAt: port.serverTime(),
      });
    } else {
      await port.mergeDoc('errorNotebook', safeId, {
        userId: uid,
        questionId: safeQuestionId,
        disciplineId: (entry.disciplineId || 'geral').slice(0, 80) || 'geral',
        topicTitle: (entry.topicTitle || 'Tópico').trim().slice(0, 200) || 'Tópico',
        questionStem: (entry.questionStem || 'Questão').trim().slice(0, 2000) || 'Questão',
        correctOption: (entry.correctOption || '-').trim().slice(0, 500) || '-',
        selectedOption: (entry.selectedOption || '-').trim().slice(0, 500) || '-',
        errorReason,
        improvementNote: (entry.improvementNote || '').slice(0, 2000),
        nextReviewDate,
        reviewCount,
        status,
        createdAt: port.serverTime(),
        updatedAt: port.serverTime(),
      });
    }
    counts.errorNotebook += 1;
  }

  // 4. topicProgress
  for (const [key, tp] of Object.entries(store.topicProgressMap || {})) {
    const safeTopicId = sanitizeMigrationId(tp.topicId || key, 'top');
    const existing = await port.readDoc('topicProgress', safeTopicId);
    const theoryDone = Boolean(tp.theoryDone || existing?.theoryDone);
    const questionsDone = Boolean(tp.questionsDone || existing?.questionsDone);
    const revisionDone = Boolean(tp.revisionDone || existing?.revisionDone);
    const masteryLevel = Math.round(
      (theoryDone ? 40 : 0) + (questionsDone ? 40 : 0) + (revisionDone ? 20 : 0)
    );
    const notes = ((tp.notes || (existing?.notes as string) || '')).slice(0, 2000);

    if (existing) {
      await port.mergeDoc('topicProgress', safeTopicId, {
        theoryDone,
        questionsDone,
        revisionDone,
        masteryLevel,
        notes,
        updatedAt: port.serverTime(),
      });
    } else {
      await port.mergeDoc('topicProgress', safeTopicId, {
        userId: uid,
        topicId: safeTopicId,
        disciplineId: (tp.disciplineId || 'geral').slice(0, 80) || 'geral',
        theoryDone,
        questionsDone,
        revisionDone,
        masteryLevel,
        notes,
        updatedAt: port.serverTime(),
      });
    }
    counts.topicProgress += 1;
  }

  // 5. studySessions (create-only in firestore.rules -> idempotent check via getDoc)
  for (const session of store.studySessions || []) {
    const safeId = sanitizeMigrationId(session.id, 'ses');
    const existing = await port.readDoc('studySessions', safeId);
    if (!existing) {
      const blockType =
        session.blockType === 'theory' ||
        session.blockType === 'questions' ||
        session.blockType === 'correction' ||
        session.blockType === 'revision'
          ? session.blockType
          : 'theory';
      const dateKey =
        session.dateKey && session.dateKey.length >= 8
          ? session.dateKey.slice(0, 20)
          : new Date().toISOString().slice(0, 10);
      await port.mergeDoc('studySessions', safeId, {
        userId: uid,
        dateKey,
        disciplineId: (session.disciplineId || 'geral').slice(0, 80) || 'geral',
        topicTitle: (session.topicTitle || 'Sessão de estudo').trim().slice(0, 200) || 'Sessão de estudo',
        blockType,
        durationMinutes: Math.max(1, Math.min(600, Math.round(session.durationMinutes || 1))),
        notes: (session.notes || '').slice(0, 1000),
        createdAt: port.serverTime(),
      });
      counts.studySessions += 1;
    }
  }

  counts.total =
    counts.readingProgress +
    counts.simuladoAttempts +
    counts.errorNotebook +
    counts.topicProgress +
    counts.studySessions;
  return counts;
}
