export function sumNumbers(values: number[]): number {
  return values.reduce((total, value) => total + value, 0);
}
