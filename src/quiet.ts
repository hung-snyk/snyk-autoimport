/**
 * Suppress the underlying library's internal progress chatter.
 *
 * `snyk-api-import` logs operational lines via console.log/warn (repo counts,
 * poll status, "No projects in org", etc.). Those are useful for its own CLI
 * but noise here — the wrapper prints its own clean status. We filter only
 * known-noisy patterns and always let unrecognised lines and console.error
 * through, so genuine problems are never hidden.
 */
const NOISE: RegExp[] = [
  /unique targets from \d+ projects/,
  /No projects in org/,
  /No targets could be generated/,
  /^Discovered \d+ projects from import job/,
  /^Checking status for import job id/,
  /^Loaded \d+ target/,
  /^Importing batch/,
  /Filtering out previously imported targets/,
];

function isNoise(args: unknown[]): boolean {
  const line = args.map((a) => String(a)).join(' ');
  return NOISE.some((re) => re.test(line));
}

/** Run `fn` with library progress chatter filtered out of stdout. */
export async function withQuietConsole<T>(fn: () => Promise<T>): Promise<T> {
  const origLog = console.log;
  const origWarn = console.warn;
  console.log = (...args: unknown[]): void => {
    if (!isNoise(args)) origLog(...(args as []));
  };
  console.warn = (...args: unknown[]): void => {
    if (!isNoise(args)) origWarn(...(args as []));
  };
  try {
    return await fn();
  } finally {
    console.log = origLog;
    console.warn = origWarn;
  }
}
