const runScanButton = document.getElementById("run-scan-btn");
const targetInput = document.getElementById("target-input");
const statusMessage = document.getElementById("status-message");
const resultsContainer = document.getElementById("results");
const lastTestId = document.getElementById("last-test-id");

document.addEventListener("DOMContentLoaded", () => {
    runScanButton.addEventListener("click", runScan);
    loadDashboardStats();
});

async function runScan() {
    const target = targetInput.value.trim();
    if (!target) {
        statusMessage.textContent = "Enter a target before running a scan.";
        return;
    }

    setBusy(true);
    statusMessage.textContent = `Running scan for ${target}...`;

    try {
        const response = await fetch("/api/tests/run", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ target }),
        });

        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || "Scan failed");
        }

        lastTestId.textContent = payload.test_id;
        renderResults(payload.results || []);
        statusMessage.textContent = `Scan completed for ${payload.target}.`;
        await loadDashboardStats();
    } catch (error) {
        resultsContainer.classList.add("empty");
        resultsContainer.innerHTML = `<p>${escapeHtml(error.message)}</p>`;
        statusMessage.textContent = "Scan failed.";
    } finally {
        setBusy(false);
    }
}

async function loadDashboardStats() {
    try {
        const response = await fetch("/api/dashboard/stats");
        const stats = await response.json();

        document.getElementById("total-tests").textContent = stats.totalTests || 0;
        document.getElementById("total-vulnerabilities").textContent = stats.totalVulnerabilities || 0;
        document.getElementById("high-count").textContent = stats.highCount || 0;
        document.getElementById("medium-count").textContent = stats.mediumCount || 0;
    } catch (_error) {
        statusMessage.textContent = "Unable to load dashboard stats.";
    }
}

function renderResults(results) {
    if (!results.length) {
        resultsContainer.classList.add("empty");
        resultsContainer.innerHTML = "<p>No vulnerabilities were reported for this target.</p>";
        return;
    }

    resultsContainer.classList.remove("empty");
    resultsContainer.innerHTML = results
        .filter((result) => result.vulnerability)
        .map(
            (result) => `
                <article class="result-card">
                    <h3>${escapeHtml(result.vulnerability)}</h3>
                    <div class="meta">
                        <span class="tag ${String(result.severity || "").toLowerCase()}">${escapeHtml(result.severity || "Unknown")}</span>
                        <span class="tag">${escapeHtml(result.module || "unknown")}</span>
                    </div>
                </article>
            `
        )
        .join("");

    if (!resultsContainer.innerHTML.trim()) {
        resultsContainer.classList.add("empty");
        resultsContainer.innerHTML = "<p>No vulnerabilities were reported for this target.</p>";
    }
}

function setBusy(isBusy) {
    runScanButton.disabled = isBusy;
    runScanButton.textContent = isBusy ? "Scanning..." : "Run Scan";
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}
