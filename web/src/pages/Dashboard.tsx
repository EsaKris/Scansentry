export default function Dashboard() {
  return (
    <div className="space-y-6">
      <div className="bg-gradient-to-r from-brand-navy to-slate-800 rounded-2xl p-8 text-white">
        <h1 className="text-3xl font-bold mb-2">Welcome to ScanSentry</h1>
        <p className="text-slate-300">Your secure QR dashboard is ready.</p>
      </div>
      <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
        <p className="text-slate-500">Your stats and analytics will appear here soon.</p>
      </div>
    </div>
  );
}