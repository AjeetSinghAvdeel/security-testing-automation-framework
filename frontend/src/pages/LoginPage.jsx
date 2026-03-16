import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";

export default function LoginPage() {
  const navigate = useNavigate();
  const {
    user,
    loginWithGoogle,
    loginWithEmail,
    registerWithEmail,
    authError,
    authBusy,
    hasFirebaseConfig,
  } = useAuth();
  const [mode, setMode] = useState("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div className="page-shell login-shell">
      <section className="login-layout">
        <div className="login-panel login-panel-copy">
          <p className="section-label">Protected Access</p>
          <h1>Private dashboard access for each analyst account.</h1>
          <p className="hero-text">
            Authentication controls scan ownership, stored history, dashboard metrics, and
            blockchain-linked evidence visibility. Each signed-in user sees only the records tied to
            that account.
          </p>

          <div className="auth-points">
            <div className="auth-point">
              <span className="auth-point-index">01</span>
              <div>
                <strong>Google or email sign-in</strong>
                <p>Use whichever provider you enabled in Firebase Authentication.</p>
              </div>
            </div>
            <div className="auth-point">
              <span className="auth-point-index">02</span>
              <div>
                <strong>User-scoped history</strong>
                <p>Scan results, counts, and blockchain evidence stay isolated per user.</p>
              </div>
            </div>
            <div className="auth-point">
              <span className="auth-point-index">03</span>
              <div>
                <strong>Frontend config required</strong>
                <p>The login page needs Firebase web-app keys in `frontend/.env.local`.</p>
              </div>
            </div>
          </div>
        </div>

        <div className="login-panel login-panel-form">
          <div className="login-mode-tabs">
            <button
              className={mode === "signin" ? "mode-tab active" : "mode-tab"}
              type="button"
              onClick={() => setMode("signin")}
            >
              Email Sign In
            </button>
            <button
              className={mode === "signup" ? "mode-tab active" : "mode-tab"}
              type="button"
              onClick={() => setMode("signup")}
            >
              Create Account
            </button>
          </div>

          <form
            className="email-form"
            onSubmit={async (event) => {
              event.preventDefault();
              const success =
                mode === "signin"
                  ? await loginWithEmail(email, password)
                  : await registerWithEmail(email, password);
              if (success) {
                navigate("/dashboard");
              }
            }}
          >
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="analyst@company.com"
            />

            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Minimum 6 characters"
            />

            <button
              className="secondary-login-button"
              type="submit"
              disabled={!hasFirebaseConfig || Boolean(authBusy)}
            >
              {authBusy === "email" || authBusy === "signup"
                ? "Authenticating..."
                : mode === "signin"
                  ? "Sign in with Email"
                  : "Create Email Account"}
            </button>
          </form>

          <div className="login-divider">
            <span>or continue with</span>
          </div>

          <button
            className="google-login-button"
            type="button"
            onClick={async () => {
              const success = await loginWithGoogle();
              if (success) {
                navigate("/dashboard");
              }
            }}
            disabled={!hasFirebaseConfig || Boolean(authBusy)}
          >
            {authBusy === "google" ? "Opening Google..." : "Continue with Google"}
          </button>

          <div className="auth-support-card">
            <strong>Connection checklist</strong>
            <ul className="auth-checklist">
              <li>Firebase Authentication has Google and Email/Password enabled.</li>
              <li>`frontend/.env.local` contains the Firebase web-app config values.</li>
              <li>The current dev domain is allowed in Firebase Authentication settings.</li>
            </ul>
          </div>

          {!hasFirebaseConfig ? (
            <p className="auth-hint">
              The login buttons are disabled because the frontend is missing the Firebase web-app
              environment values. Add them to `frontend/.env.local` and restart Vite.
            </p>
          ) : null}

          {authError ? <p className="auth-hint auth-hint-error">{authError}</p> : null}
        </div>
      </section>
    </div>
  );
}
