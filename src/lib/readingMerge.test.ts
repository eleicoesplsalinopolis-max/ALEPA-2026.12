import { describe, expect, it } from 'vitest';
import { mergeById } from './readingMerge';

describe('mergeById', () => {
  it('merges distinct highlights from two devices without losing either', () => {
    const server = [
      { id: 'hl_dev1_1', page: 4, quote: 'Art. 5º da Constituição' },
    ];
    const local = [
      { id: 'hl_dev2_1', page: 12, quote: 'Regimento Interno ALEPA' },
    ];
    const merged = mergeById(server, local);
    expect(merged.map((i) => i.id)).toEqual(['hl_dev1_1', 'hl_dev2_1']);
  });

  it('prefers local version when the same id exists on server and local', () => {
    const server = [{ id: 'an_1', content: 'Rascunho antigo' }];
    const local = [{ id: 'an_1', content: 'Nota atualizada' }];
    const merged = mergeById(server, local);
    expect(merged).toEqual([{ id: 'an_1', content: 'Nota atualizada' }]);
  });

  it('respects explicit removed IDs so deleted items are not resurrected', () => {
    const server = [
      { id: 'bm_1', page: 3 },
      { id: 'bm_2', page: 9 },
    ];
    const local = [{ id: 'bm_2', page: 9 }];
    const merged = mergeById(server, local, ['bm_1']);
    expect(merged).toEqual([{ id: 'bm_2', page: 9 }]);
  });

  it('caps the merged array length to the specified limit', () => {
    const server = Array.from({ length: 10 }, (_, idx) => ({ id: `s_${idx}` }));
    const local = Array.from({ length: 10 }, (_, idx) => ({ id: `l_${idx}` }));
    const merged = mergeById(server, local, [], 5);
    expect(merged).toHaveLength(5);
  });
});
