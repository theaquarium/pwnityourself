'use client';
import { useState } from 'react';
import type { Block, ExecResult } from '../lib/api';

type RunBlock = Extract<Block, { type: 'run' }>;

export default function RunCell({
  block,
  enabled,
  onRun,
}: {
  block: RunBlock;
  enabled: boolean;
  onRun: (b: RunBlock) => Promise<ExecResult>;
}) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ExecResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      setResult(await onRun(block));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed');
    } finally {
      setRunning(false);
    }
  }

  const output = result ? (result.stdout + (result.stderr ? '\n' + result.stderr : '')).trimEnd() : '';
  const pwned = /uid=\d+\(/.test(output);

  return (
    <div className="run-cell">
      <div className="rc-head">
        <div>
          <span className="rc-title">{block.title}</span>
          <span className="rc-badge">{block.kind === 'background' ? 'background server' : 'run'}</span>
        </div>
        <button className="btn primary rc-run-btn" onClick={run} disabled={!enabled || running}>
          {running ? <span className="spinner" /> : null}
          {running ? 'Running…' : result || error ? 'Run again' : 'Run'}
        </button>
      </div>
      <div className="rc-cmd">
        <span className="prompt">$ </span>
        {block.command}
      </div>
      {block.explain ? <div className="rc-explain">{block.explain}</div> : null}
      {!enabled ? <div className="rc-explain hint">Start the lab (top right) to enable this step.</div> : null}

      {error ? (
        <div className="rc-output">
          <div className="o-head">
            <span>error</span>
          </div>
          <pre style={{ color: '#f4a2a6' }}>{error}</pre>
        </div>
      ) : result ? (
        <div className="rc-output">
          <div className="o-head">
            <span>output</span>
            <span className={`exit-chip ${result.exit_code === 0 ? 'ok' : 'bad'}`}>
              exit {result.exit_code}
            </span>
          </div>
          <pre className={pwned ? 'pwned' : undefined}>{output || '(no output)'}</pre>
        </div>
      ) : null}
    </div>
  );
}
