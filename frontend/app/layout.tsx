import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'PIY — Pwn It Yourself',
  description: 'Interactive, hands-on walkthroughs of real exploits against real sandboxed containers.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
