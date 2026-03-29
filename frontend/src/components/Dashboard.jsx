import { useEffect, useRef, useState } from "react";
import {
  getBlockchainStatus,
  getDashboardStats,
  getModules,
  getSession,
  getScanDetails,
  getScanStatus,
  getTests,
  runScan,
} from "../services/api";
import { useAuth } from "../auth/AuthProvider";
import ScanForm from "./ScanForm";
import ScanResults from "./ScanResults";

const initialStatus = {
  state: "idle",
  message: "Ready to run a security scan.",
};

export default function Dashboard() {
  const { token } = useAuth();
  const [stats, setStats] = useState({
    totalTests: 0,
    totalVulnerabilities: 0,
    highCount: 0,
    blockchainRecords: 0,
    siemAlerts: 0,
    complianceMappings: 0,
    reportsGenerated: 0,
  });
  const [sessionUser, setSessionUser] = useState(null);
  const [results, setResults] = useState([]);
  const [activeScan, setActiveScan] = useState(null);
  const [modules, setModules] = useState([]);
  const [tests, setTests] = useState([]);
  const [blockchainStatus, setBlockchainStatus] = useState({
    connected: false,
    evidence_count: 0,
  });
  const [status, setStatus] = useState(initialStatus);
  const [activeTestId, setActiveTestId] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const pollerRef = useRef(null);

  useEffect(() => {
    if (!token) {
      return undefined;
    }

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
  }, [token]);

  async function loadDashboard() {
    try {
      const [
        statsPayload,
        modulesPayload,
        testsPayload,
        blockchainPayload,
        sessionPayload,
      ] = await Promise.all([
        getDashboardStats(token),
        getModules(token),
        getTests(token),
        getBlockchainStatus(token),
        getSession(token),
      ]);

      const tests = testsPayload.tests || [];
      const siemAlerts = tests.reduce(
        (count, test) => count + (test.siem?.alerts?.length || 0),
        0,
      );
      const complianceMappings = tests.reduce(
        (count, test) => count + (test.siem?.compliance?.length || 0),
        0,
      );
      const reportsGenerated = tests.reduce(
        (count, test) => count + (test.siem?.report ? 1 : 0),
        0,
      );

      setStats({
        totalTests: statsPayload.totalTests || 0,
        totalVulnerabilities: statsPayload.totalVulnerabilities || 0,
        highCount: statsPayload.highCount || 0,
        blockchainRecords: statsPayload.blockchainRecords || 0,
        siemAlerts,
        complianceMappings,
        reportsGenerated,
      });
      setModules(modulesPayload.modules || []);
      setTests(tests);
      setBlockchainStatus(blockchainPayload);
      setSessionUser(sessionPayload.user || null);
    } catch (error) {
      setStatus({
        state: "failed",
        message: error.message,
      });
    }
  }

  async function handleRunScan({ target, attackProfile, attackLabel }) {
    if (!target.trim()) {
      setStatus({
        state: "failed",
        message: "Enter a target IP or URL first.",
      });
      return;
    }

    setIsRunning(true);
    setResults([]);
    setActiveScan(null);
    setStatus({
      state: "running",
      message: `Performing ${attackLabel} against ${target}...`,
    });

    try {
      const scan = await runScan(token, target.trim(), attackProfile);
      setActiveTestId(scan.test_id);
      startPolling(scan.test_id, target.trim(), attackLabel);
    } catch (error) {
      setIsRunning(false);
      setStatus({
        state: "failed",
        message: error.message,
      });
    }
  }

  function startPolling(testId, target, attackLabel) {
    if (pollerRef.current) {
      window.clearInterval(pollerRef.current);
    }

    pollerRef.current = window.setInterval(async () => {
      try {
        const scanStatus = await getScanStatus(token, testId);
        if (scanStatus.status === "completed") {
          window.clearInterval(pollerRef.current);
          pollerRef.current = null;

          const details = await getScanDetails(token, testId);
          setResults(details.results || []);
          setActiveScan(details);
          setIsRunning(false);
          const actionCount = details.lab_actions?.length || 0;
          const authenticatedActions = (details.lab_actions || []).filter(
            (action) => action.outcome === "authenticated" || action.outcome === "authorized",
          ).length;
          setStatus({
            state: "completed",
            message:
              actionCount > 0
                ? `Completed ${attackLabel} for ${target}. ${actionCount} lab actions recorded${authenticatedActions ? `, ${authenticatedActions} reached authenticated features` : ""}.`
                : `Completed ${attackLabel} for ${target}.`,
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
            message: `Performing ${attackLabel} for ${target}. Status: ${scanStatus.status}`,
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
      <section className="dashboard-overview panel">
        <div>
          <p className="section-label">Dashboard</p>
          <h2>{sessionUser?.name || "Analyst"}'s command center</h2>
          <p className="panel-subtitle">
            Only your scans, your evidence trail, and your blockchain-linked records are visible in this workspace.
          </p>
        </div>
      </section>

      <ScanForm onRunScan={handleRunScan} status={status} isRunning={isRunning} />

      <section className="stats-grid">
        <StatCard label="Total scans" value={stats.totalTests} accent="blue" />
        <StatCard
          label="Vulnerabilities detected"
          value={stats.totalVulnerabilities}
          accent="slate"
        />
        <StatCard label="High severity alerts" value={stats.highCount} accent="red" />
        <StatCard label="SIEM alerts" value={stats.siemAlerts} accent="teal" />
        <StatCard label="Compliance mappings" value={stats.complianceMappings} accent="amber" />
        <StatCard label="Reports generated" value={stats.reportsGenerated} accent="violet" />
        <StatCard
          label={blockchainStatus.connected ? "Blockchain records" : "Blockchain offline records"}
          value={stats.blockchainRecords}
          accent="green"
        />
      </section>

      <section className="layout-grid">
        <ScanResults results={results} activeTestId={activeTestId} activeScan={activeScan} />


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

          <AnimatedHistoryList
            items={tests.slice(0, 10)}
            onSelect={(test) => {
              setActiveTestId(test.test_id);
              setResults(test.results || []);
              setActiveScan(test);
            }}
          />
        </section>
      </section>
    </main>
  );
}

function StatCard({ label, value, accent = "blue" }) {
  return (
    <article className={`stat-card stat-card-${accent}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function AnimatedHistoryList({ items, onSelect }) {
  const listRef = useRef(null);
  const [topFade, setTopFade] = useState(0);
  const [bottomFade, setBottomFade] = useState(items.length > 4 ? 1 : 0);

  useEffect(() => {
    const node = listRef.current;
    if (!node) {
      return;
    }

    const hasOverflow = node.scrollHeight > node.clientHeight + 2;
    setBottomFade(hasOverflow ? 1 : 0);
    setTopFade(0);
  }, [items]);

  function handleScroll(event) {
    const node = event.currentTarget;
    const { scrollTop, scrollHeight, clientHeight } = node;
    setTopFade(Math.min(scrollTop / 50, 1));
    const remaining = scrollHeight - (scrollTop + clientHeight);
    setBottomFade(scrollHeight <= clientHeight ? 0 : Math.min(remaining / 50, 1));
  }

  return (
    <div className="history-scroll-shell">
      <div className="history-scroll-list" ref={listRef} onScroll={handleScroll}>
        {items.map((test, index) => (
          <button
            className="history-scroll-item"
            key={test.test_id}
            type="button"
            onClick={() => onSelect(test)}
            style={{ animationDelay: `${index * 60}ms` }}
          >
            <div className="history-scroll-row">
              <strong>{test.target}</strong>
              <span>{formatAttackLabel(test.attack_profile)}</span>
            </div>
            <div className="history-scroll-row history-scroll-row-muted">
              <span>{test.status}</span>
              <span>{test.result_count || 0} findings</span>
            </div>
          </button>
        ))}
      </div>
      <div className="history-fade history-fade-top" style={{ opacity: topFade }} />
      <div className="history-fade history-fade-bottom" style={{ opacity: bottomFade }} />
    </div>
  );
}

function formatAttackLabel(value) {
  return value ? value.replaceAll("_", " ") : "attack";
}
