export function clamp(value: number, min: number, max: number): number {
  if (min > max) {
    [min, max] = [max, min];
  }
  return Math.min(max, Math.max(min, value));
}
