type SearchValue = number | string | null | undefined;

export function matchesSearchQuery(normalizedQuery: string, ...values: SearchValue[]): boolean {
  if (!normalizedQuery) {
    return true;
  }

  return values.some((value) =>
    String(value ?? "")
      .toLowerCase()
      .includes(normalizedQuery)
  );
}
