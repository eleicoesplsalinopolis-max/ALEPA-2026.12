export interface SearchMatchRange {
  start: number;
  end: number;
}

export function normalizeSearchString(raw: string): string {
  return raw
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

export function normalizeSearchTextWithMap(raw: string): {
  normalized: string;
  indexMap: number[];
} {
  let normalized = '';
  const indexMap: number[] = [];

  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    const stripped = ch
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase();
    for (let j = 0; j < stripped.length; j += 1) {
      normalized += stripped[j];
      indexMap.push(i);
    }
  }

  return { normalized, indexMap };
}

export function findAccentInsensitiveMatches(
  haystack: string,
  needle: string
): SearchMatchRange[] {
  const normNeedle = normalizeSearchString(needle).replace(/\s+/g, ' ').trim();
  if (normNeedle.length < 2 || !haystack) return [];

  const { normalized, indexMap } = normalizeSearchTextWithMap(haystack);
  const matches: SearchMatchRange[] = [];
  let pos = normalized.indexOf(normNeedle);

  while (pos !== -1) {
    const start = indexMap[pos];
    const lastNormIdx = pos + normNeedle.length - 1;
    const end = (indexMap[lastNormIdx] ?? start) + 1;
    if (start !== undefined && end > start) {
      matches.push({ start, end });
    }
    pos = normalized.indexOf(normNeedle, pos + normNeedle.length);
  }

  return matches;
}

interface SpanRangeMap {
  spanIdx: number;
  localOffset: number;
}

export function applyTextLayerSearchHighlights(
  container: HTMLElement | null,
  query: string,
  scrollToFirst = false
): number {
  if (!container) return 0;

  const allSpans = Array.from(container.querySelectorAll('span')).filter(
    (el) => el.dataset.origText !== undefined || el.childElementCount === 0
  );

  // Restore clean original text on every span before re-highlighting
  for (const span of allSpans) {
    if (span.dataset.origText === undefined) {
      span.dataset.origText = span.textContent ?? '';
    } else if (span.querySelector('mark[data-pdf-search-highlight="true"]')) {
      span.textContent = span.dataset.origText;
    }
  }

  const trimmed = query.trim();
  if (trimmed.length < 2 || allSpans.length === 0) {
    return 0;
  }

  const nonEmptySpans = allSpans.filter((s) => (s.dataset.origText ?? '').length > 0);
  if (nonEmptySpans.length === 0) return 0;

  let combined = '';
  const charOwners: Array<SpanRangeMap | null> = [];

  for (let sIdx = 0; sIdx < nonEmptySpans.length; sIdx += 1) {
    const text = nonEmptySpans[sIdx].dataset.origText ?? '';
    if (
      combined.length > 0 &&
      !/\s$/.test(combined) &&
      !/^\s/.test(text)
    ) {
      combined += ' ';
      charOwners.push(null);
    }
    for (let c = 0; c < text.length; c += 1) {
      combined += text[c];
      charOwners.push({ spanIdx: sIdx, localOffset: c });
    }
  }

  const matches = findAccentInsensitiveMatches(combined, trimmed);
  if (matches.length === 0) return 0;

  const perSpanRanges = new Map<number, SearchMatchRange[]>();

  for (let mIdx = 0; mIdx < matches.length; mIdx += 1) {
    const match = matches[mIdx];
    for (let pos = match.start; pos < match.end; pos += 1) {
      const owner = charOwners[pos];
      if (!owner) continue;
      let list = perSpanRanges.get(owner.spanIdx);
      if (!list) {
        list = [];
        perSpanRanges.set(owner.spanIdx, list);
      }
      const last = list[list.length - 1];
      if (last && last.end === owner.localOffset) {
        last.end = owner.localOffset + 1;
      } else {
        list.push({ start: owner.localOffset, end: owner.localOffset + 1 });
      }
    }
  }

  let firstMarkEl: HTMLElement | null = null;
  const doc = container.ownerDocument ?? document;

  perSpanRanges.forEach((ranges, sIdx) => {
    const span = nonEmptySpans[sIdx];
    const text = span.dataset.origText ?? '';
    const frag = doc.createDocumentFragment();
    let cursor = 0;

    for (const range of ranges) {
      if (range.start > cursor) {
        frag.appendChild(doc.createTextNode(text.slice(cursor, range.start)));
      }
      const mark = doc.createElement('mark');
      mark.dataset.pdfSearchHighlight = 'true';
      mark.className = firstMarkEl
        ? 'pdf-search-mark'
        : 'pdf-search-mark pdf-search-mark-active';
      mark.textContent = text.slice(range.start, range.end);
      if (!firstMarkEl) {
        firstMarkEl = mark;
      }
      frag.appendChild(mark);
      cursor = range.end;
    }

    if (cursor < text.length) {
      frag.appendChild(doc.createTextNode(text.slice(cursor)));
    }

    span.textContent = '';
    span.appendChild(frag);
  });

  if (scrollToFirst && firstMarkEl) {
    try {
      (firstMarkEl as HTMLElement).scrollIntoView({
        behavior: 'smooth',
        block: 'center',
        inline: 'center',
      });
    } catch {
      // ignore scrollIntoView in non-browser environments
    }
  }

  return matches.length;
}
