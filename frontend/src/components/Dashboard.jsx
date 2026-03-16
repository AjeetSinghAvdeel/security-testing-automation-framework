import { useEffect, useRef, useState } from "react";
import {
  getDashboardStats,
  getModules,
  getScanDetails,
  getScanStatus,
  getTests,
  runScan,
} from "../services/api";
import ScanForm from "./ScanForm";
import ScanResults from "./ScanResults";

const initialStatus = {
  state: "idle",
  message: "Ready to run a security scan.",
};

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalTests: 0,
    totalVulnerabilities: 0,
    highCount: 0,
  });
  const [results, setResults] = useState([]);
  const [modules, setModules] = useState([]);
  const [tests, setTests] = useState([]);
  const [status, setStatus] = useState(initialStatus);
  const [activeTestId, setActiveTestId] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const pollerRef = useRef(null);

  useEffect(() => {
    void loadDashboard();
    const refreshInterval = window.setInterval(() => {
      void loadDashboard();
    }, 5000);

    return () => {
      window.clearInterval(refreshInterval);
      if (pollerRef.current) {
        window.clearInterval(pollerRef.current);
      }
    };
  }, []);

  async function loadDashboard() {
    try {
      const [statsPayload, modulesPayload, testsPayload] = await Promise.all([
        getDashboardStats(),
        getModules(),
        getTests(),
      ]);

      setStats({
        totalTests: statsPayload.totalTests || 0,
        totalVulnerabilities: statsPayload.totalVulnerabilities || 0,
        highCount: statsPayload.highCount || 0,
      });
      setModules(modulesPayload.modules || []);
      setTests(testsPayload.tests || []);
    } catch (error) {
      setStatus({
        state: "failed",
        message: error.message,
      });
    }
  }

  async function handleRunScan(target) {
    if (!target.trim()) {
      setStatus({
        state: "failed",
        message: "Enter a target IP or URL first.",
      });
      return;
    }

    setIsRunning(true);
    setResults([]);
    setStatus({
      state: "running",
      message: `Running scan against ${target}...`,
    });

    try {
      const scan = await runScan(target.trim());
      setActiveTestId(scan.test_id);
      startPolling(scan.test_id, target.trim());
    } catch (error) {
      setIsRunning(false);
      setStatus({
        state: "failed",
        message: error.message,
      });
    }
  }

  function startPolling(testId, target) {
    if (pollerRef.current) {
      window.clearInterval(pollerRef.current);
    }

    pollerRef.current = window.setInterval(async () => {
      try {
        const scanStatus = await getScanStatus(testId);

        if (scanStatus.status === "completed") {
          window.clearInterval(pollerRef.current);
          pollerRef.current = null;

          const details = await getScanDetails(testId);
          setResults(details.results || []);
          setIsRunning(false);
          setStatus({
            state: "completed",
            message: `Completed scan for ${target}.`,
          });
          await loadDashboard();
        } else if (scanStatus.status === "failed") {
          window.clearInterval(pollerRef.current);
          pollerRef.current = null;

          setIsRunning(false);
          setStatus({
            state: "failed",
            message: `Scan failed for ${target}.`,
          });
        } else {
          setStatus({
            state: "running",
            message: `Running scan for ${target}. Status: ${scanStatus.status}`,
          });
        }
      } catch (error) {
        window.clearInterval(pollerRef.current);
        pollerRef.current = null;

        setIsRunning(false);
        setStatus({
          state: "failed",
          message: error.message,
        });
      }
    }, 2000);
  }

  return (
    <main className="dashboard">
      <ScanForm onRunScan={handleRunScan} status={status} isRunning={isRunning} />

      <section className="stats-grid">
        <StatCard label="Total scans" value={stats.totalTests} />
        <StatCard label="Vulnerabilities detected" value={stats.totalVulnerabilities} />
        <StatCard label="High severity alerts" value={stats.highCount} />
      </section>

      <section className="layout-grid">
        <ScanResults results={results} activeTestId={activeTestId} />

        <section className="panel side-panel">
          <div className="panel-header">
            <div>
              <p className="section-label">Modules</p>
              <h2>Backend module availability</h2>
            </div>
          </div>

          <div className="module-list">
            {modules.map((module) => (
              <article className="module-card" key={module.name}>
                <div>
                  <strong>{module.name}</strong>
                  <p>{module.path}</p>
                </div>
                <span className={module.loaded ? "module-ok" : "module-off"}>
                  {module.loaded ? "Loaded" : "Unavailable"}
                </span>
              </article>
            ))}
          </div>

          <div className="panel-divider" />

          <div className="panel-header">
            <div>
              <p className="section-label">Recent scans</p>
              <h2>Persisted history</h2>
            </div>
          </div>

          <div className="history-list">
            {tests.slice(0, 6).map((test) => (
              <button
                className="history-card"
                key={test.test_id}
                type="button"
                onClick={() => {
                  setActiveTestId(test.test_id);
                  setResults(test.results || []);
                }}
              >
                <strong>{test.target}</strong>
                <span>{test.status}</span>
                <small>{test.result_count || 0} findings</small>
              </button>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}

function StatCard({ label, value }) {
  return (
    <article className="stat-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}
