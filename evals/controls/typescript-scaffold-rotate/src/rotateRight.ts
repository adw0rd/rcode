export function rotateRight<T>(values: T[], k: number): T[] {
  const length = values.length;
  if (length === 0) {
    return [];
  }

  const shift = ((Math.trunc(k) % length) + length) % length;
  if (shift === 0) {
    return values.slice();
  }
  return values.slice(length - shift).concat(values.slice(0, length - shift));
}
