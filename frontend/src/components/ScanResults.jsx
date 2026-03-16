import VulnerabilityCard from "./VulnerabilityCard";

export default function ScanResults({ results, activeTestId }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="section-label">Results</p>
          <h2>Vulnerability findings</h2>
        </div>
        <span className="test-pill">
          {activeTestId ? `Test ID: ${activeTestId}` : "No scan started"}
        </span>
      </div>

      {!results.length ? (
        <div className="empty-state">
          <p>No vulnerabilities to display yet.</p>
          <p>Run a scan to populate this panel.</p>
        </div>
      ) : (
        <div className="results-grid">
          {results.map((item, index) => (
            <VulnerabilityCard
              key={`${item.vulnerability || "result"}-${index}`}
              item={item}
            />
          ))}
        </div>
      )}
    </section>
  );
}
