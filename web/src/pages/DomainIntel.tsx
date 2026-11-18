import { useState } from 'react';
import { Search, ShieldAlert, ShieldCheck, Globe, AlertTriangle, } from 'lucide-react';
import api from '../services/api';

export default function DomainIntel() {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<any>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;
    
    setIsLoading(true);
    setError('');
    setReport(null);

    try {
      const response = await api.post('/domains/analyze/', { 
        value: domain,
        refresh: false 
      });
      console.log("Domain Report:", response.data);
      setReport(response.data);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to analyze domain. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto">
      <div className="mb-8 text-center mt-8">
        <h1 className="text-3xl font-bold text-brand-navy mb-2">Domain Intelligence</h1>
        <p className="text-slate-500 max-w-xl mx-auto">
          Check the security and registration health of any domain before you trust it. 
          We analyze DNS, SSL, and threat intelligence.
        </p>
      </div>

      {/* Search Bar */}
      <form onSubmit={handleAnalyze} className="max-w-2xl mx-auto mb-12">
        <div className="relative flex items-center shadow-lg rounded-xl overflow-hidden">
          <Globe className="w-6 h-6 text-slate-400 absolute left-4" />
          <input
            type="text"
            required
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="w-full pl-14 pr-32 py-4 bg-white border-0 focus:ring-0 text-lg text-brand-navy placeholder-slate-400"
            placeholder="Enter a domain (e.g. suspicious-site.com)"
          />
          <button
            type="submit"
            disabled={isLoading}
            className="absolute right-2 px-6 py-2.5 bg-brand-teal hover:bg-teal-600 text-white font-medium rounded-lg transition-colors disabled:opacity-70 flex items-center gap-2"
          >
            {isLoading ? 'Analyzing...' : 'Analyze'}
            {!isLoading && <Search className="w-4 h-4" />}
          </button>
        </div>
      </form>

      {error && (
        <div className="max-w-2xl mx-auto mb-8 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center gap-3 text-red-700">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Report Display */}
      {report && (
        <div className="bg-white rounded-2xl shadow-xl border border-slate-200 overflow-hidden">
          {/* Header */}
          <div className="p-8 border-b border-slate-100 bg-slate-50 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
              <h2 className="text-2xl font-bold text-brand-navy break-all">{report.domain || domain}</h2>
              <p className="text-sm text-slate-500 mt-1">Assessment completed</p>
            </div>
            
            {/* We will use this classification badge */}
            <div className={`px-4 py-2 rounded-full font-bold text-sm flex items-center gap-2 ${
              report.risk_classification === 'clean' ? 'bg-green-100 text-green-800' :
              report.risk_classification === 'malicious' ? 'bg-red-100 text-red-800' :
              'bg-yellow-100 text-yellow-800'
            }`}>
              {report.risk_classification === 'clean' ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
              {report.risk_classification?.toUpperCase() || 'UNKNOWN'}
            </div>
          </div>

          {/* The rest of the report data will go here, we'll build the visual layout in the next step */}
          <div className="p-8">
            <pre className="bg-slate-900 text-green-400 p-4 rounded-lg overflow-auto text-sm">
              {JSON.stringify(report, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}