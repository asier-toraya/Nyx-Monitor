export function buildVirusTotalSearchUrl(query: string): string {
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(query)}`;
}
