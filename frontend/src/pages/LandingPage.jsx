import { Link } from "react-router-dom";

const features = [
  "Web, IAM, and IoT scan orchestration",
  "Firebase-backed user history and audit persistence",
  "Blockchain evidence hashing with Ganache integration",
  "Real-time scan progress and per-user dashboard views",
];

const workflow = [
  {
    title: "Authenticate",
    description: "Enter through Google or email login and unlock a private dashboard tied to your account.",
  },
  {
    title: "Run scans",
    description: "Launch safe simulations against approved lab targets and monitor live execution updates.",
  },
  {
    title: "Review evidence",
    description: "Inspect findings, blockchain-linked evidence, and user-specific historical records.",
  },
];

const pillars = [
  {
    title: "Unified execution engine",
    body: "A modular backend drives Web, IAM, IoT, SIEM, and blockchain flows through a single orchestration layer.",
  },
  {
    title: "Persistent analyst workspace",
    body: "Firebase-backed identity and storage keep every run linked to the analyst who triggered it.",
  },
  {
    title: "Evidence-oriented reporting",
    body: "Completed scans can be hashed and attached to blockchain records for later verification and review.",
  },
];

const capabilities = [
  "Live status polling",
  "User-scoped dashboards",
  "Blockchain evidence records",
  "Firebase-backed history",
  "IoT module integration",
  "Web and IAM module support",
];

const governanceHighlights = [
  {
    title: "SIEM-ready telemetry",
    body: "Each completed scan can emit alert and log artifacts that are ready for downstream review workflows.",
  },
  {
    title: "Compliance alignment",
    body: "Mapped findings connect vulnerabilities to NIST and ISO 27001 controls for presentation and audit review.",
  },
  {
    title: "Executive summaries",
    body: "Report summaries package findings, alert counts, and evidence context into one scan-centered view.",
  },
];

export default function LandingPage() {
  return (
    <div className="page-shell landing-shell">
      <section className="landing-hero">
        <div className="landing-copy">
          <p className="hero-kicker">IoT & Web Security Testing Framework</p>
          <h1>Audit, track, and review security simulations through one guided platform.</h1>
          <p className="hero-text">
            This project combines modular scan execution, blockchain evidence, Firebase-backed
            persistence, and a dedicated analyst dashboard for educational security testing labs.
          </p>
          <div className="hero-actions">
            <Link className="primary-action" to="/login">
              Enter Secure Workspace
            </Link>
            <a className="secondary-action" href="#features">
              Explore Features
            </a>
          </div>
        </div>

        <div className="hero-visual">
          <div className="visual-card visual-card-large">
            <span>Live scanning</span>
            <strong>Real-time execution pipeline</strong>
          </div>
          <div className="visual-card visual-card-mid">
            <span>Per-user data</span>
            <strong>Isolated history and blockchain records</strong>
          </div>
          <div className="visual-card visual-card-small">
            <span>Evidence</span>
            <strong>SHA-256 + Ganache</strong>
          </div>
        </div>
      </section>

      <section className="feature-section" id="features">
        <div className="section-intro">
          <p className="section-label">Project Features</p>
          <h2>Built to demonstrate the full security testing workflow.</h2>
        </div>

        <div className="feature-grid">
          {features.map((feature) => (
            <article className="feature-card" key={feature}>
              <div className="feature-orb" />
              <h3>{feature}</h3>
            </article>
          ))}
        </div>
      </section>

      <section className="platform-section">
        <div className="section-intro">
          <p className="section-label">Why It Matters</p>
          <h2>A classroom-ready platform with enough structure to feel like a real analyst console.</h2>
        </div>

        <div className="pillar-grid">
          {pillars.map((pillar) => (
            <article className="pillar-card" key={pillar.title}>
              <h3>{pillar.title}</h3>
              <p>{pillar.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="workflow-section">
        <div className="section-intro">
          <p className="section-label">Workflow</p>
          <h2>A complete analyst journey instead of a single screen.</h2>
        </div>

        <div className="workflow-grid">
          {workflow.map((step, index) => (
            <article className="workflow-card" key={step.title}>
              <span className="workflow-index">0{index + 1}</span>
              <h3>{step.title}</h3>
              <p>{step.description}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="systems-section">
        <div className="systems-copy">
          <p className="section-label">System View</p>
          <h2>Authentication, scanning, persistence, and evidence collection work as one flow.</h2>
          <p className="hero-text">
            The frontend controls user access, the backend executes scans asynchronously, Firebase
            stores user-specific history, and Ganache can receive evidence-linked records for later
            audit review.
          </p>
        </div>

        <div className="systems-board">
          {capabilities.map((capability) => (
            <div className="system-chip" key={capability}>
              {capability}
            </div>
          ))}
        </div>
      </section>

      <section className="platform-section">
        <div className="section-intro">
          <p className="section-label">SIEM And Governance</p>
          <h2>Operational logging, compliance context, and reporting are now part of the scan lifecycle.</h2>
        </div>

        <div className="pillar-grid">
          {governanceHighlights.map((item) => (
            <article className="pillar-card" key={item.title}>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="cta-section">
        <div className="cta-card">
          <p className="section-label">Ready</p>
          <h2>Sign in and keep every scan attached to the analyst who ran it.</h2>
          <p className="hero-text">
            Use a Firebase web app config on the frontend and the service account key on the backend
            for a complete auth and storage flow.
          </p>
          <Link className="primary-action" to="/login">
            Go to Login
          </Link>
        </div>
      </section>
    </div>
  );
}
