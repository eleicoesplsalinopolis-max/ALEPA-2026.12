import { describe, expect, it } from 'vitest';
import {
  applyTextLayerSearchHighlights,
  findAccentInsensitiveMatches,
} from './pdfSearchHighlight';

interface MockNode {
  nodeType: 'text' | 'element' | 'fragment';
  tagName?: string;
  className?: string;
  dataset: Record<string, string | undefined>;
  children: MockNode[];
  _text: string;
  ownerDocument: MockDoc;
  appendChild: (child: MockNode) => MockNode;
  append: (...nodes: MockNode[]) => void;
  querySelectorAll: (selector: string) => MockNode[];
  querySelector: (selector: string) => MockNode | null;
  get childElementCount(): number;
  get textContent(): string;
  set textContent(v: string);
}

interface MockDoc {
  createElement: (tag: string) => MockNode;
  createTextNode: (text: string) => MockNode;
  createDocumentFragment: () => MockNode;
}

function createMockDoc(): MockDoc {
  const makeNode = (
    nodeType: 'text' | 'element' | 'fragment',
    tagName = '',
    text = ''
  ): MockNode => {
    const node: MockNode = {
      nodeType,
      tagName: tagName.toLowerCase(),
      className: '',
      dataset: {},
      children: [],
      _text: text,
      ownerDocument: doc,
      appendChild(child: MockNode) {
        if (child.nodeType === 'fragment') {
          this.children.push(...child.children);
        } else {
          this.children.push(child);
        }
        return child;
      },
      append(...nodes: MockNode[]) {
        for (const n of nodes) this.appendChild(n);
      },
      querySelectorAll(selector: string) {
        const res: MockNode[] = [];
        const walk = (n: MockNode) => {
          for (const c of n.children) {
            if (
              selector === 'span' &&
              c.nodeType === 'element' &&
              c.tagName === 'span'
            ) {
              res.push(c);
            } else if (
              selector === 'mark[data-pdf-search-highlight="true"]' &&
              c.nodeType === 'element' &&
              c.tagName === 'mark' &&
              c.dataset.pdfSearchHighlight === 'true'
            ) {
              res.push(c);
            }
            walk(c);
          }
        };
        walk(this);
        return res;
      },
      querySelector(selector: string) {
        return this.querySelectorAll(selector)[0] ?? null;
      },
      get childElementCount() {
        return this.children.filter((c) => c.nodeType === 'element').length;
      },
      get textContent() {
        if (this.nodeType === 'text') return this._text;
        if (this.children.length === 0) return this._text;
        return this.children.map((c) => c.textContent).join('');
      },
      set textContent(v: string) {
        this._text = v;
        this.children = [];
      },
    };
    return node;
  };

  const doc: MockDoc = {
    createElement: (tag: string) => makeNode('element', tag, ''),
    createTextNode: (text: string) => makeNode('text', '', text),
    createDocumentFragment: () => makeNode('fragment', '', ''),
  };
  return doc;
}

describe('pdfSearchHighlight helpers', () => {
  it('matches accented Portuguese terms case- and accent-insensitively with exact original bounds', () => {
    const text = 'Art. 1º A Constituição Estadual e a administração pública da ALEPA.';
    const matches = findAccentInsensitiveMatches(text, 'constituicao');
    expect(matches).toHaveLength(1);
    expect(text.slice(matches[0].start, matches[0].end)).toBe('Constituição');

    const adminMatches = findAccentInsensitiveMatches(text, 'ADMINISTRACAO');
    expect(adminMatches).toHaveLength(1);
    expect(text.slice(adminMatches[0].start, adminMatches[0].end)).toBe('administração');
  });

  it('highlights search terms across single and split PDF.js text layer spans cleanly', () => {
    const doc = createMockDoc();
    const container = doc.createElement('div');
    const s1 = doc.createElement('span');
    s1.textContent = 'Poder';
    const s2 = doc.createElement('span');
    s2.textContent = 'Legislativo';
    const s3 = doc.createElement('span');
    s3.textContent = 'do Pará e Comissão';
    container.append(s1, s2, s3);

    const count = applyTextLayerSearchHighlights(
      container as unknown as HTMLElement,
      'poder legislativo'
    );
    expect(count).toBe(1);
    const marks = container.querySelectorAll('mark[data-pdf-search-highlight="true"]');
    expect(marks.length).toBe(2);
    expect(marks[0].textContent).toBe('Poder');
    expect(marks[1].textContent).toBe('Legislativo');

    // Re-running with a different term restores original text first
    const secondCount = applyTextLayerSearchHighlights(
      container as unknown as HTMLElement,
      'comissao'
    );
    expect(secondCount).toBe(1);
    const updatedMarks = container.querySelectorAll('mark[data-pdf-search-highlight="true"]');
    expect(updatedMarks.length).toBe(1);
    expect(updatedMarks[0].textContent).toBe('Comissão');
    expect(s1.textContent).toBe('Poder');
    expect(s2.textContent).toBe('Legislativo');
  });
});
