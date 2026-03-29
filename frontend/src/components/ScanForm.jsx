import { useMemo, useState } from "react";

const attackCatalog = [
  {
    genre: "Broken Authentication",
    options: [
      {
        value: "credential_stuffing",
        label: "Credential Stuffing",
        description: "Sprays common credential pairs against the Juice Shop login API.",
      },
      {
        value: "password_strength",
        label: "Password Strength",
        description: "Attempts the known weak admin password path on the local lab.",
      },
      {
        value: "exposed_credentials",
        label: "Exposed Credentials",
        description: "Tests the exposed testing credentials challenge against the live lab.",
      },
      {
        value: "login_mc_safesearch",
        label: "Login MC SafeSearch",
        description: "Uses the MC SafeSearch challenge credentials against the login flow.",
      },
      {
        value: "bruteforce",
        label: "Brute-force Controls",
        description: "Performs repeated login attempts and checks whether the lab throttles them.",
      },
    ],
  },
  {
    genre: "Injection",
    options: [
      {
        value: "login_admin_sqli",
        label: "Login Admin",
        description: "Uses SQL injection-style login payloads against the Juice Shop auth endpoint.",
      },
      {
        value: "union_search_injection",
        label: "Union Search Injection",
        description: "Sends union-based payloads to the product search endpoint.",
      },
    ],
  },
  {
    genre: "XSS",
    options: [
      {
        value: "reflected_xss",
        label: "Reflected XSS",
        description: "Sends active XSS payloads through the search flow and checks reflection.",
      },
    ],
  },
  {
    genre: "Broken Access Control",
    options: [
      {
        value: "admin_section",
        label: "Admin Section",
        description: "Probes admin-oriented endpoints without an authenticated browser session.",
      },
      {
        value: "view_basket",
        label: "View Basket",
        description: "Authenticates and then tampers the basket id to test basket ownership checks.",
      },
    ],
  },
  {
    genre: "Improper Input Validation",
    options: [
      {
        value: "empty_user_registration",
        label: "Empty User Registration",
        description: "Attempts a blank-account registration against the Juice Shop user API.",
      },
    ],
  },
  {
    genre: "Observability Failures",
    options: [
      {
        value: "exposed_metrics",
        label: "Exposed Metrics",
        description: "Checks whether the Prometheus metrics endpoint is exposed on the lab.",
      },
    ],
  },
  {
    genre: "Security Misconfiguration",
    options: [
      {
        value: "application_configuration",
        label: "Application Configuration",
        description: "Checks whether the application-configuration endpoint is publicly exposed.",
      },
    ],
  },
];

export default function ScanForm({ onRunScan, status, isRunning }) {
  const defaultTarget =
    window.location.port === "3000" ? "http://localhost:3000" : "http://localhost:3000";
  const [target, setTarget] = useState(defaultTarget);
  const [genre, setGenre] = useState(attackCatalog[0].genre);
  const [attackProfile, setAttackProfile] = useState(attackCatalog[0].options[0].value);

  const activeGenre = useMemo(
    () => attackCatalog.find((entry) => entry.genre === genre) || attackCatalog[0],
    [genre],
  );

  const availableAttacks = activeGenre.options;
  const selectedAttack =
    availableAttacks.find((entry) => entry.value === attackProfile) || availableAttacks[0];

  function handleGenreChange(event) {
    const nextGenre = event.target.value;
    setGenre(nextGenre);
    const nextOptions = attackCatalog.find((entry) => entry.genre === nextGenre)?.options || [];
    if (nextOptions.length) {
      setAttackProfile(nextOptions[0].value);
    }
  }

  function handleSubmit(event) {
    event.preventDefault();
    onRunScan({
      target,
      attackProfile,
      attackLabel: selectedAttack.label,
    });
  }

  return (
    <section className="panel panel-accent">
      <div className="scan-header">
        <div className="section-copy">
          <p className="section-label">Attack Control</p>
          <h2>Perform a local-lab attack flow against a safe target.</h2>
          <p className="section-note">
            Attack genres and techniques map to live Juice Shop actions, not just passive scan labels.
          </p>
        </div>

        <div className="scan-chip-group">
          <span className="scan-chip">Local Lab</span>
          <span className="scan-chip scan-chip-muted">Action Trace</span>
        </div>
      </div>

      <form className="scan-form" onSubmit={handleSubmit}>
        <label htmlFor="target">Target IP or URL</label>
        <div className="scan-form-row">
          <input
            id="target"
            name="target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="http://localhost:3000"
          />
          <button type="submit" disabled={isRunning}>
            {isRunning ? "Performing..." : `Perform ${selectedAttack.label}`}
          </button>
        </div>

        <div className="scan-select-grid">
          <label className="scan-select-field" htmlFor="attackGenre">
            <span>Attack Genre</span>
            <select id="attackGenre" value={genre} onChange={handleGenreChange}>
              {attackCatalog.map((entry) => (
                <option key={entry.genre} value={entry.genre}>
                  {entry.genre}
                </option>
              ))}
            </select>
          </label>

          <label className="scan-select-field" htmlFor="attackType">
            <span>Attack Type</span>
            <select
              id="attackType"
              value={selectedAttack.value}
              onChange={(event) => setAttackProfile(event.target.value)}
            >
              {availableAttacks.map((entry) => (
                <option key={entry.value} value={entry.value}>
                  {entry.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <p className="scan-profile-note">{selectedAttack.description}</p>
      </form>

      <p className={`status-banner ${status.state}`}>{status.message}</p>
    </section>
  );
}
