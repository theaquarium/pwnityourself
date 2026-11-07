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

export interface LessonSummary {
  slug: string;
  title: string;
  subtitle: string;
  cve: string;
  meta: string;
}

export interface Lesson extends LessonSummary {
  blocks: Block[];
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  exit_code: number;
}

export async function getLessons(): Promise<LessonSummary[]> {
  const r = await fetch('/api/lessons');
  if (!r.ok) throw new Error('failed to load lessons');
  return r.json();
}

export async function getLesson(slug: string): Promise<Lesson> {
  const r = await fetch(`/api/lesson/${slug}`);
  if (!r.ok) throw new Error('failed to load lesson');
  return r.json();
}

export async function startSession(slug: string): Promise<{ session_id: string; slug: string; timeout: number }> {
  const r = await fetch('/api/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ slug }),
  });
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    throw new Error(e.detail || 'failed to start lab');
  }
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
