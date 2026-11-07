export function formatList(items: string[]): string {
  let result = '';
  for (let i = 0; i < items.length; i++) {
    if (i > 0) result = result + ', ';
    result = result + items[i];
  }
  return result;
}
