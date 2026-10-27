type LoginPageProps = {
  error?: string;
  onLogin: () => void;
};

function ShieldGlyph() {
  return <svg viewBox="0 0 72 72" fill="none" aria-hidden="true"><path d="M36 7 58 15v16c0 14.2-9.7 25.8-22 30C23.7 56.8 14 45.2 14 31V15L36 7Z" stroke="currentColor" strokeWidth="2" /><path d="m24 35 8 8 17-18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /><circle cx="36" cy="36" r="28" stroke="currentColor" strokeOpacity=".14" /></svg>;
}

export default function LoginPage({ error, onLogin }: LoginPageProps) {
  return (
    <main className="login-shell">
      <div className="login-grid-glow" />
      <section className="login-story">
        <div className="brand-lockup login-brand">
          <div className="brand-mark"><span></span><span></span><span></span><span></span></div>
          <div><div className="brand-name">LeakPath</div><div className="brand-kicker">SECURITY OBSERVATORY</div></div>
        </div>
        <div className="login-story-copy">
          <div className="eyebrow"><span className="eyebrow-line"></span> PRIVATE WORKSPACE ACCESS</div>
          <h1>Keep the signal<br /><em>inside the path.</em></h1>
          <p>Sign in to review sensitive-data findings, Git exposure paths, and live workspace telemetry from your protected observatory.</p>
        </div>
        <div className="login-proof-row"><div><strong>01</strong><span>EXPLAINABLE<br />RISK</span></div><div><strong>02</strong><span>REDACTED<br />EVIDENCE</span></div><div><strong>03</strong><span>SAFE<br />SIMULATION</span></div></div>
      </section>
      <section className="login-card-wrap">
        <div className="login-card">
          <div className="login-orbit"><ShieldGlyph /><span className="orbit-pip pip-one"></span><span className="orbit-pip pip-two"></span><span className="orbit-pip pip-three"></span></div>
          <div className="card-label">OPERATOR AUTHENTICATION</div>
          <h2>Enter the observatory</h2>
          <p className="login-card-copy">Use your Manus account to continue. LeakPath does not store passwords or create a separate credential system.</p>
          {error && <div className="login-error"><span></span>{error}</div>}
          <button className="login-button" onClick={onLogin}><span className="manus-glyph">M</span><span>Continue with Manus</span><span className="login-arrow">↗</span></button>
          <div className="login-divider"><span></span><small>SECURE OAUTH HANDSHAKE</small><span></span></div>
          <div className="login-boundary"><span className="status-dot"></span><div><strong>Your workspace is isolated</strong><p>Only the app-owned synthetic demo workspace is monitored. No real files or credentials are touched.</p></div></div>
        </div>
        <div className="login-foot"><span>LEAKPATH / DEFENSIVE DEVSECOPS</span><span>MANUS ACCOUNT LOGIN</span></div>
      </section>
    </main>
  );
}
