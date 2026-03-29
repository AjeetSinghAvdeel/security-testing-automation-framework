function resolveApiBaseUrl() {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }

  if (typeof window === "undefined") {
    return "";
  }

  const { hostname, port } = window.location;

  if ((hostname === "localhost" || hostname === "127.0.0.1") && port !== "5000") {
    return "http://127.0.0.1:5000";
  }

  return "";
}

const API_BASE_URL = resolveApiBaseUrl();

async function request(path, token, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
  const contentType = response.headers.get("content-type") || "";
  let payload;

  if (contentType.includes("application/json")) {
    payload = await response.json();
  } else {
    const text = await response.text();
    const preview = text.slice(0, 80).replace(/\s+/g, " ").trim();
    throw new Error(
      `API returned ${contentType || "non-JSON content"} instead of JSON. ${preview}`,
    );
  }

  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }

  return payload;
}

export function runScan(token, target, attackProfile) {
  return request("/api/tests/run", token, {
    method: "POST",
    body: JSON.stringify({ target, attackProfile }),
  });
}

export function getScanStatus(token, testId) {
  return request(`/api/tests/status/${testId}`, token);
}

export function getScanDetails(token, testId) {
  return request(`/api/tests/${testId}`, token);
}

export function getDashboardStats(token) {
  return request("/api/dashboard/stats", token);
}

export function getModules(token) {
  return request("/api/modules", token);
}

export function getTests(token) {
  return request("/api/tests", token);
}

export function getBlockchainStatus(token) {
  return request("/api/blockchain/status", token);
}

export function getSession(token) {
  return request("/api/auth/session", token);
}
