'use client';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import { getLessons, type LessonSummary } from './lib/api';

export default function Home() {
  const [lessons, setLessons] = useState<LessonSummary[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getLessons().then(setLessons).catch(() => setErr('Could not load the labs.'));
  }, []);

  return (
    <>
      <header className="site-header">
        <div className="inner">
          <Link href="/" className="brand">
            <span className="mark">PIY</span>
            <span className="sub">Pwn It Yourself</span>
          </Link>
        </div>
      </header>

      <main className="article">
        <div className="title-block">
          <h1>Pwn It Yourself</h1>
          <p className="subtitle">
            Interactive, hands-on walkthroughs of real software exploits. Each lab spins up a real,
            deliberately-vulnerable target in an isolated sandbox and lets you fire the exploit yourself,
            step by step, and watch the victim execute your commands.
          </p>
        </div>

        {err ? <p style={{ color: '#b22a2f' }}>{err}</p> : null}
        {!lessons ? (
          <p className="hint">Loading…</p>
        ) : (
          <div className="lesson-list">
            {lessons.map((l) => (
              <Link key={l.slug} href={`/lesson/${l.slug}`} className="lesson-card">
                <span className="cve-tag">{l.cve}</span>
                <h2>{l.title}</h2>
                <p className="lc-sub">{l.subtitle}</p>
                <p className="meta">{l.meta}</p>
              </Link>
            ))}
          </div>
        )}
      </main>
    </>
  );
}
