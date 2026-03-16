import VulnerabilityCard from "./VulnerabilityCard";

export default function ScanResults({ results, activeTestId, activeScan }) {
  const highRiskCount = results.filter(
    (item) => item.severity === "Critical" || item.severity === "High",
  ).length;
  const targetLabel = activeScan?.target || results[0]?.target || "Unknown target";
  const statusLabel = activeScan?.status || (results.length ? "completed" : "idle");

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="section-label">Results</p>
          <h2>Vulnerability findings</h2>
          <p className="panel-subtitle">
            {results.length
              ? `${results.length} findings in focus, including ${highRiskCount} high-risk items.`
              : "Run a scan to build a result set and inspect findings here."}
          </p>
        </div>
        <div className="result-meta">
          <span className="test-pill">
            {activeTestId ? `Test ID: ${activeTestId}` : "No scan started"}
          </span>
          {results.length ? <span className="result-count-pill">{results.length} findings</span> : null}
        </div>
      </div>

      {!results.length ? (
        <div className="empty-state">
          <p>No vulnerabilities to display yet.</p>
          <p>Run a scan to populate this panel.</p>
        </div>
      ) : (
        <details className="scan-result-card">
          <summary className="scan-result-summary">
            <div className="scan-result-summary-main">
              <p className="vuln-eyebrow">Scanned Target</p>
              <strong>{targetLabel}</strong>
              <span className="scan-result-subtitle">
                {results.length} findings recorded for this scan.
              </span>
            </div>

            <div className="scan-result-badges">
              <span className="scan-result-badge">{statusLabel}</span>
              <span className="scan-result-badge">
                {highRiskCount} high severity
              </span>
            </div>
          </summary>

          <div className="scan-result-details">
            <div className="results-grid">
              {results.map((item, index) => (
                <VulnerabilityCard
                  key={`${item.vulnerability || "result"}-${index}`}
                  item={item}
                />
              ))}
            </div>
          </div>
        </details>
      )}
    </section>
  );
}
