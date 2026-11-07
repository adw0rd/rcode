export function uniqueStable(values: number[]): number[] {
  return [...new Set(values)].sort((a, b) => a - b);
}
