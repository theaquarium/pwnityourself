export type Block =
  | { type: 'markdown'; content: string }
  | { type: 'code'; language: string; title: string; content: string }
  | {
      type: 'run';
      title: string;
      kind: 'background' | 'foreground';
      command: string;
      explain: string;
      logfile?: string;
    };

export interface Lesson {
  slug: string;
  title: string;
  subtitle: string;
  cve: string;
  meta: string;
  blocks: Block[];
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exit_code: number;
}

export async function getLesson(): Promise<Lesson> {
  const r = await fetch('/api/lesson');
  if (!r.ok) throw new Error('failed to load lesson');
  return r.json();
}

export async function startSession(): Promise<{ session_id: string; timeout: number }> {
  const r = await fetch('/api/session', { method: 'POST' });
  if (!r.ok) throw new Error('failed to start lab');
  return r.json();
}

export async function execCell(
  sid: string,
  body: { command: string; background?: boolean; logfile?: string | null }
): Promise<ExecResult> {
  const r = await fetch(`/api/session/${sid}/exec`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.detail || 'command failed');
  }
  return r.json();
}

export async function endSession(sid: string): Promise<void> {
  await fetch(`/api/session/${sid}`, { method: 'DELETE' });
}
