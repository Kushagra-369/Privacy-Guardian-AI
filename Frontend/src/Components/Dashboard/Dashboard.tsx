import { useState } from "react";
import RiskCard from "../Cards/RiskCard";

const Dashboard = () => {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = () => {
    setLoading(true);

    setTimeout(() => {
      setData({
        name: "example.com",
        risk: Math.floor(Math.random() * 100),
        permissions: ["Cookies", "Location", "Camera"],
      });
      setLoading(false);
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-black flex flex-col items-center justify-center gap-6">
      <h1 className="text-3xl text-white font-bold">
        Privacy Guardian AI
      </h1>

      <button
        onClick={handleScan}
        className="bg-blue-600 px-4 py-2 rounded-xl text-white hover:bg-blue-700"
      >
        {loading ? "Scanning..." : "Scan Website"}
      </button>

      {data && <RiskCard {...data} />}
    </div>
  );
};

export default Dashboard;