'use client';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

export default function CodeBlock({
  title,
  language,
  content,
}: {
  title: string;
  language: string;
  content: string;
}) {
  return (
    <div className="code-card">
      <div className="head">
        <span style={{ opacity: 0.6 }}>●●●</span>
        <span className="fname">{title}</span>
      </div>
      <SyntaxHighlighter
        language={language}
        style={oneDark}
        customStyle={{ fontSize: 13, background: '#0e1116', padding: '16px 18px', margin: 0 }}
        wrapLongLines={false}
      >
        {content.trimEnd()}
      </SyntaxHighlighter>
    </div>
  );
}
