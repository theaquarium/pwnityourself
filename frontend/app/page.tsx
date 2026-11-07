'use client';
import { useEffect, useRef, useState } from 'react';
import {
  getLesson,
  startSession,
  endSession,
  execCell,
  type Lesson,
  type Block,
  type ExecResult,
} from './lib/api';
import Markdown from './components/Markdown';
import CodeBlock from './components/CodeBlock';
import RunCell from './components/RunCell';

type Status = 'idle' | 'booting' | 'ready' | 'error';
type RunBlock = Extract<Block, { type: 'run' }>;

export default function Page() {
  const [lesson, setLesson] = useState<Lesson | null>(null);
  const [status, setStatus] = useState<Status>('idle');
  const [sid, setSid] = useState<string | null>(null);
  const [remaining, setRemaining] = useState<number>(0);
  const [err, setErr] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    getLesson().then(setLesson).catch(() => setErr('Could not load the lesson.'));
  }, []);

  useEffect(() => {
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, []);

  async function startLab() {
    setStatus('booting');
    setErr(null);
    try {
      const s = await startSession();
      setSid(s.session_id);
      setStatus('ready');
      setRemaining(s.timeout);
      if (timer.current) clearInterval(timer.current);
      timer.current = setInterval(() => {
        setRemaining((r) => {
          if (r <= 1) {
            if (timer.current) clearInterval(timer.current);
            setStatus('idle');
            setSid(null);
            return 0;
          }
          return r - 1;
        });
      }, 1000);
    } catch (e: any) {
      setStatus('error');
      setErr(e.message || 'Failed to start the lab.');
    }
  }

  async function resetLab() {
    if (sid) await endSession(sid).catch(() => {});
    if (timer.current) clearInterval(timer.current);
    setSid(null);
    setStatus('idle');
    setRemaining(0);
  }

  async function runCell(b: RunBlock): Promise<ExecResult> {
    if (!sid) throw new Error('No active lab session.');
    return execCell(sid, {
      command: b.command,
      background: b.kind === 'background',
      logfile: b.logfile ?? null,
    });
  }

  const mm = String(Math.floor(remaining / 60)).padStart(2, '0');
  const ss = String(remaining % 60).padStart(2, '0');

  const statusLabel =
    status === 'idle' ? 'No lab running'
    : status === 'booting' ? 'Spinning up sandbox…'
    : status === 'ready' ? `Sandbox live · ${mm}:${ss}`
    : 'Error';

  return (
    <>
      <header className="site-header">
        <div className="inner">
          <div className="brand">
            <span className="mark">PIY</span>
            <span className="sub">Pwn It Yourself</span>
          </div>
          <div className="header-right">
            <span className="status">
              <span className={`dot ${status}`} />
              {statusLabel}
            </span>
            {status === 'ready' ? (
              <button className="btn ghost" onClick={resetLab}>Reset lab</button>
            ) : (
              <button className="btn primary" onClick={startLab} disabled={status === 'booting'}>
                {status === 'booting' ? 'Starting…' : 'Start lab'}
              </button>
            )}
          </div>
        </div>
      </header>

      {status === 'ready' && sid ? (
        <div className="lab-banner">
          <div className="inner">
            <span>Live sandbox <code>{sid}</code> — an isolated throwaway container. It self-destructs when the timer runs out.</span>
          </div>
        </div>
      ) : null}

      <main className="article">
        {err ? <p style={{ color: '#b22a2f' }}>{err}</p> : null}
        {!lesson ? (
          <p className="hint">Loading…</p>
        ) : (
          <>
            <div className="title-block">
              <span className="cve-tag">{lesson.cve}</span>
              <h1>{lesson.title}</h1>
              <p className="subtitle">{lesson.subtitle}</p>
              <p className="meta">{lesson.meta}</p>
            </div>

            {lesson.blocks.map((b, i) => {
              if (b.type === 'markdown') return <Markdown key={i} content={b.content} />;
              if (b.type === 'code')
                return <CodeBlock key={i} title={b.title} language={b.language} content={b.content} />;
              if (b.type === 'run')
                return <RunCell key={i} block={b} enabled={status === 'ready'} onRun={runCell} />;
              return null;
            })}
          </>
        )}
      </main>
    </>
  );
}
