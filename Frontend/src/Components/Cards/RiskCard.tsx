type Props = {
  name: string;
  risk: number;
  permissions: string[];
};

const RiskCard = ({ name, risk, permissions }: Props) => {
  return (
    <div className="bg-gray-900 text-white p-6 rounded-2xl shadow-lg w-[350px]">
      <h2 className="text-xl font-bold mb-2">{name}</h2>

      <p className="mb-2">
        Risk Score:{" "}
        <span className="text-yellow-400 font-semibold">{risk}%</span>
      </p>

      <div>
        <p className="font-semibold mb-1">Data Access:</p>
        <ul className="list-disc list-inside text-sm text-gray-300">
          {permissions.map((perm, index) => (
            <li key={index}>{perm}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default RiskCard;