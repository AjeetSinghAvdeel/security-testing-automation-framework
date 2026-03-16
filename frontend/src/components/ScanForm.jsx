import { useState } from "react";

export default function ScanForm({ onRunScan, status, isRunning }) {
  const defaultTarget =
    window.location.port === "8080" ? "http://frontend" : "http://localhost";
  const [target, setTarget] = useState(defaultTarget);

  function handleSubmit(event) {
    event.preventDefault();
    onRunScan(target);
  }

  return (
    <section className="panel panel-accent">
      <div className="section-copy">
        <p className="section-label">Scan Control</p>
        <h2>Launch a security scan against a safe local target.</h2>
      </div>

      <form className="scan-form" onSubmit={handleSubmit}>
        <label htmlFor="target">Target IP or URL</label>
        <div className="scan-form-row">
          <input
            id="target"
            name="target"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="localhost or 192.168.1.50"
          />
          <button type="submit" disabled={isRunning}>
            {isRunning ? "Running..." : "Run Security Scan"}
          </button>
        </div>
      </form>

      <p className={`status-banner ${status.state}`}>{status.message}</p>
    </section>
  );
}
