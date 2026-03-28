import { useState } from "react";

export function useSearchQuery(initialValue = "") {
  const [query, setQuery] = useState(initialValue);

  return {
    query,
    setQuery,
    normalizedQuery: query.trim().toLowerCase()
  };
}
