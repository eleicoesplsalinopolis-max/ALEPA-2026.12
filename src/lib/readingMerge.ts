export function mergeById<T extends { id: string }>(
  server: T[] = [],
  local: T[] = [],
  removed: string[] = [],
  cap = 150
): T[] {
  const map = new Map<string, T>();
  [...server, ...local].forEach((i) => {
    if (!removed.includes(i.id)) {
      map.set(i.id, i);
    }
  });
  return [...map.values()].slice(0, cap);
}
