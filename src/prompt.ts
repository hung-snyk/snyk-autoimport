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

/** Strips escape sequences (arrow keys, bracketed-paste markers) from input. */
const ESCAPE_SEQUENCE = /\u001b\[[0-9;]*[~A-Za-z]/g;

/**
 * Prompt for a secret, echoing one `*` per character.
 *
 * Reads raw keypresses rather than going through readline. readline's
 * `_refreshLine` writes cursor-reset and clear-screen codes straight to the
 * output stream, so the usual trick of stubbing `_writeToOutput` to hide the
 * echo also erases the prompt on any real terminal, leaving a blank line that
 * looks like a hang. Masking here keeps the prompt visible and gives the
 * feedback that being fully silent did not.
 */
export async function askSecret(question: string): Promise<string> {
  const input = process.stdin;
  const output = process.stdout;

  // Piped input has no keypresses to mask; read it as an ordinary line so the
  // command stays usable from a script.
  if (!input.isTTY) {
    return ask(question);
  }

  output.write(question);
  const wasRaw = Boolean(input.isRaw);
  input.setRawMode(true);
  input.resume();
  input.setEncoding('utf8');

  return new Promise<string>((resolve, reject) => {
    let value = '';

    const finish = (fn: () => void): void => {
      input.setRawMode(wasRaw);
      input.pause();
      input.removeListener('data', onData);
      output.write('\n');
      fn();
    };

    function onData(chunk: string): void {
      for (const ch of chunk.replace(ESCAPE_SEQUENCE, '')) {
        switch (ch) {
          case '\r':
          case '\n':
            return finish(() => resolve(value.trim()));
          case '\u0003': // Ctrl-C
            return finish(() => reject(new Error('Cancelled.')));
          case '\u0004': // Ctrl-D
            return finish(() =>
              value ? resolve(value.trim()) : reject(new Error('Cancelled.')),
            );
          case '\u007f': // Backspace
          case '\b':
            if (value) {
              value = value.slice(0, -1);
              output.write('\b \b');
            }
            break;
          default:
            // Ignore remaining control characters, e.g. a stray tab or bell.
            if (ch >= ' ') {
              value += ch;
              output.write('*');
            }
        }
      }
    }

    input.on('data', onData);
  });
}

export async function confirm(question: string): Promise<boolean> {
  const answer = (await ask(`${question} (Y/n) `)).toLowerCase();
  return answer === '' || answer === 'y' || answer === 'yes';
}
