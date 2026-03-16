import VulnerabilityCard from "./VulnerabilityCard";

export default function ScanResults({ results, activeTestId, activeScan }) {
  const highRiskCount = results.filter(
    (item) => item.severity === "Critical" || item.severity === "High",
  ).length;
  const targetLabel = activeScan?.target || results[0]?.target || "Unknown target";
  const statusLabel = activeScan?.status || (results.length ? "completed" : "idle");
  const siemPayload = activeScan?.siem;
  const siemAlerts = siemPayload?.alerts || [];
  const complianceMappings = siemPayload?.compliance || [];
  const reportSummary = siemPayload?.report || null;
  const siemLogs = siemPayload?.logs || [];

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
            {siemPayload ? (
              <div className="analysis-grid">
                <article className="analysis-card">
                  <p className="vuln-eyebrow">SIEM Alerts</p>
                  <h3>{siemAlerts.length || 0} high-risk alerts</h3>
                  <p className="analysis-copy">
                    High and critical findings are transformed into alert artifacts for downstream
                    investigation.
                  </p>
                  {siemAlerts.length ? (
                    <div className="analysis-list">
                      {siemAlerts.slice(0, 4).map((alert) => (
                        <div className="analysis-item" key={alert.alert_id || alert.timestamp}>
                          <strong>{alert.vulnerability || "Security alert"}</strong>
                          <span>{alert.severity || "Unknown"} severity</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="analysis-empty">No high-severity alerts were generated for this scan.</p>
                  )}
                </article>

                <article className="analysis-card">
                  <p className="vuln-eyebrow">Compliance Mapping</p>
                  <h3>{complianceMappings.length || 0} mapped findings</h3>
                  <p className="analysis-copy">
                    Findings are mapped against NIST and ISO 27001 controls for audit-oriented review.
                  </p>
                  {complianceMappings.length ? (
                    <div className="analysis-list">
                      {complianceMappings.slice(0, 4).map((mapping, index) => (
                        <div
                          className="analysis-item analysis-item-compact"
                          key={`${mapping.vulnerability || "mapping"}-${index}`}
                        >
                          <strong>{mapping.vulnerability || "Finding"}</strong>
                          <span>NIST: {(mapping.nist_controls || []).join(", ") || "Not mapped"}</span>
                          <span>ISO: {(mapping.iso27001_controls || []).join(", ") || "Not mapped"}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="analysis-empty">No compliance mappings are attached to this scan yet.</p>
                  )}
                </article>

                <article className="analysis-card">
                  <p className="vuln-eyebrow">Report Summary</p>
                  <h3>{reportSummary?.report_id || "Summary pending"}</h3>
                  <p className="analysis-copy">
                    Post-processing generates a compact scan report with severity breakdown and
                    evidence-linked context.
                  </p>
                  {reportSummary ? (
                    <div className="summary-metrics">
                      <div className="summary-metric">
                        <span>Findings</span>
                        <strong>{reportSummary.total_findings || results.length}</strong>
                      </div>
                      <div className="summary-metric">
                        <span>Alerts</span>
                        <strong>{reportSummary.alerts_generated || siemAlerts.length}</strong>
                      </div>
                      <div className="summary-metric">
                        <span>Logs</span>
                        <strong>{siemLogs.length}</strong>
                      </div>
                    </div>
                  ) : (
                    <p className="analysis-empty">No report summary was generated for this scan.</p>
                  )}
                </article>
              </div>
            ) : null}

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
