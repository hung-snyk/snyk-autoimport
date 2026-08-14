/**
 * Minimal interactive prompts over Node's readline. Kept dependency-free for
 * now; a richer prompt library can swap in later without touching callers.
 */
import * as readline from 'readline';

export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

export async function ask(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  try {
    return (await new Promise<string>((resolve) => rl.question(question, resolve))).trim();
  } finally {
    rl.close();
  }
}

/** Prompt without echoing the typed characters (for tokens). */
export async function askSecret(question: string): Promise<string> {
  process.stdout.write(question);
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
  });
  // Suppress echo by intercepting the output stream writes for this prompt.
  const rlAny = rl as unknown as { _writeToOutput?: (s: string) => void };
  rlAny._writeToOutput = () => {};
  try {
    const answer = await new Promise<string>((resolve) =>
      rl.question('', resolve),
    );
    process.stdout.write('\n');
    return answer.trim();
  } finally {
    rl.close();
  }
}

export async function confirm(question: string): Promise<boolean> {
  const answer = (await ask(`${question} (Y/n) `)).toLowerCase();
  return answer === '' || answer === 'y' || answer === 'yes';
}
