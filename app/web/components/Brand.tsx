// Brand mark + tagline. The terminal-frame icon mirrors what app/icon.tsx
// produces for the PWA homescreen icon, so the in-app header and the
// installed app icon share a silhouette.

export function Brand() {
  return (
    <header className="brand">
      <div className="brand__mark" aria-hidden>
        <span className="bracket bracket--left" />
        <span className="dot" />
        <span className="bar" />
        <span className="bracket bracket--right" />
      </div>
      <div className="brand__copy">
        <h1 className="brand__name">PERSONHOOD</h1>
        <p className="brand__tag">
          Proving you’re a person <em>without</em> proving who you are.
        </p>
      </div>
      <style jsx>{`
        .brand {
          display: flex;
          gap: var(--s-4);
          align-items: flex-start;
          padding: var(--s-5) var(--s-5) var(--s-4);
          border-bottom: 1px solid var(--border);
          position: relative;
          animation: fade-up var(--t-slow) var(--ease-out) both;
        }
        .brand__mark {
          position: relative;
          width: 48px;
          height: 48px;
          flex-shrink: 0;
          display: grid;
          place-items: center;
          background: var(--bg-elev);
          border: 1px solid var(--border-strong);
          border-radius: var(--r-2);
        }
        .bracket {
          position: absolute;
          top: 8px;
          bottom: 8px;
          width: 8px;
          border-color: var(--accent);
          border-style: solid;
          border-width: 0;
        }
        .bracket--left {
          left: 8px;
          border-left-width: 2px;
          border-top-width: 2px;
          border-bottom-width: 2px;
          border-top-left-radius: 3px;
          border-bottom-left-radius: 3px;
        }
        .bracket--right {
          right: 8px;
          border-right-width: 2px;
          border-top-width: 2px;
          border-bottom-width: 2px;
          border-top-right-radius: 3px;
          border-bottom-right-radius: 3px;
        }
        .dot {
          position: absolute;
          top: 14px;
          width: 8px;
          height: 8px;
          background: var(--accent);
          border-radius: 50%;
          box-shadow: 0 0 12px var(--accent);
        }
        .bar {
          position: absolute;
          top: 24px;
          bottom: 12px;
          width: 4px;
          background: var(--accent);
          border-radius: 2px;
        }
        .brand__copy {
          display: flex;
          flex-direction: column;
          gap: 2px;
          min-width: 0;
        }
        .brand__name {
          font-family: var(--f-mono);
          font-weight: 600;
          font-size: 16px;
          letter-spacing: 0.16em;
          margin: 0;
          color: var(--ink);
        }
        .brand__tag {
          margin: 0;
          font-size: 13px;
          color: var(--ink-muted);
          line-height: 1.4;
          max-width: 30ch;
        }
        .brand__tag em {
          color: var(--accent);
          font-style: normal;
          font-weight: 600;
        }
      `}</style>
    </header>
  );
}
