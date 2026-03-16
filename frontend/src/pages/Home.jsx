import Dashboard from "../components/Dashboard";
import Navbar from "../components/Navbar";

export default function Home() {
  return (
    <div className="app-shell">
      <Navbar />
      <Dashboard />
    </div>
  );
}
