/**
 * Minimal async helpers.
 *
 * `snyk-api-import` used `p-map` and `sleep-promise` for this. Both are a few
 * lines each; reimplementing them keeps this project's dependency list at the
 * four direct packages it already has rather than inheriting transitive ones.
 */

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Map over `items` with at most `concurrency` in flight at once, preserving
 * input order in the result.
 *
 * Unlike `p-map`'s default, this never short-circuits: `fn` is expected to
 * handle its own errors. A throw here rejects the whole batch, which is why
 * both callers catch per item and record a failure instead.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const limit = Math.max(1, Math.floor(concurrency));
  const results = new Array<R>(items.length);
  let next = 0;

  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await fn(items[index], index);
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, () => worker()),
  );
  return results;
}
