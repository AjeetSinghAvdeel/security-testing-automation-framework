import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";

export default function Navbar() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  return (
    <header className="navbar">
      <div className="navbar-copy">
        <p className="navbar-kicker">Secure Analyst Workspace</p>
        <h1>IoT & Web Security Testing Framework</h1>
        <p className="navbar-subtitle">
          Logged in as {user?.displayName || user?.email || "analyst"} with a private scan history.
        </p>
      </div>

      <div className="navbar-actions">
        <div className="user-chip">
          <span className="user-chip-dot" />
          {user?.displayName || user?.email || "Analyst"}
        </div>
        <button
          className="secondary-action"
          type="button"
          onClick={async () => {
            await logout();
            navigate("/login");
          }}
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
