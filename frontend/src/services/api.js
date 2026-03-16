const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, options);
  const payload = await response.json();

  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }

  return payload;
}

export function runScan(target) {
  return request("/api/tests/run", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ target }),
  });
}

export function getScanStatus(testId) {
  return request(`/api/tests/status/${testId}`);
}

export function getScanDetails(testId) {
  return request(`/api/tests/${testId}`);
}

export function getDashboardStats() {
  return request("/api/dashboard/stats");
}

export function getModules() {
  return request("/api/modules");
}
