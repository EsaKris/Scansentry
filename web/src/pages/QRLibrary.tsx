import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Plus, Download, Pause, Play, Trash2, ExternalLink, Calendar, Search } from 'lucide-react';
import api from '../services/api';

interface QRCodeData {
  id: string;
  name: string;
  qr_type: string;
  code_mode: string;
  status: string;
  current_destination: string;
  public_url: string | null;
  created_at: string;
  last_scanned_at: string | null;
}

export default function QRLibrary() {
  const [qrCodes, setQrCodes] = useState<QRCodeData[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Fetch QR codes when the page loads
  useEffect(() => {
    fetchQRCodes();
  }, []);

   const fetchQRCodes = async () => {
    try {
      setIsLoading(true);
      setError('');
      console.log("1. Fetching QR codes...");
      
      const response = await api.get('/qr/');
      console.log("2. Backend response:", response.data);
      
      // This handles BOTH plain arrays and paginated objects
      const data = Array.isArray(response.data) ? response.data : response.data.results;
      setQrCodes(data || []);
      
    } catch (err: any) {
      console.error("3. Error:", err);
      setError(err.response?.data?.detail || 'Failed to load QR codes. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle Pause / Activate toggle
  const handleToggleStatus = async (id: string, currentStatus: string) => {
    try {
      const endpoint = currentStatus === 'active' ? 'pause' : 'activate';
      await api.post(`/qr/${id}/${endpoint}/`);
      
      // Update the UI instantly without fetching the whole list again
      setQrCodes(qrCodes.map(qr => 
        qr.id === id 
          ? { ...qr, status: currentStatus === 'active' ? 'paused' : 'active' } 
          : qr
      ));
    } catch (err) {
      alert('Failed to update status.');
    }
  };

  // Handle Download PNG
  const handleDownload = (id: string, name: string) => {
    // We use a direct link to her backend for the image download
    const token = localStorage.getItem('access_token');
    const downloadUrl = `${import.meta.env.VITE_API_URL}/qr/${id}/image/png/?download=true`;
    
    // Create a temporary link element to trigger the download
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.setAttribute('download', `${name}.png`);
    
    // Note: Since this requires auth, we fetch it via Axios and create a blob
    api.get(`/qr/${id}/image/png/`, { responseType: 'blob' })
      .then((response) => {
        const url = window.URL.createObjectURL(new Blob([response.data]));
        link.href = url;
        document.body.appendChild(link);
        link.click();
        link.remove();
      })
      .catch(() => alert('Failed to download image.'));
  };

  // Filter codes based on search
  const filteredCodes = qrCodes.filter(qr => 
    qr.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    qr.current_destination.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (isLoading) {
    return <div className="flex justify-center py-20 text-slate-500">Loading your QR codes...</div>;
  }

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
        <div>
          <h1 className="text-2xl font-bold text-brand-navy">QR Library</h1>
          <p className="text-slate-500">Manage all your generated QR codes.</p>
        </div>
        <Link 
          to="/studio" 
          className="flex items-center gap-2 px-4 py-2.5 bg-brand-teal hover:bg-teal-600 text-white font-medium rounded-lg transition-colors"
        >
          <Plus className="w-5 h-5" />
          Create New QR
        </Link>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
          {error}
        </div>
      )}

      {/* Search Bar */}
      <div className="relative mb-6">
        <Search className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Search by name or destination..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-teal/50 focus:border-brand-teal transition"
        />
      </div>

      {/* Empty State */}
      {filteredCodes.length === 0 && (
        <div className="text-center py-20 bg-white rounded-xl border border-slate-200 border-dashed">
          <div className="w-16 h-16 bg-slate-50 rounded-full flex items-center justify-center mx-auto mb-4">
            <Download className="w-8 h-8 text-slate-300" />
          </div>
          <h3 className="text-lg font-medium text-brand-navy mb-1">No QR codes yet</h3>
          <p className="text-slate-500 mb-6">Create your first secure QR code to get started.</p>
          <Link to="/studio" className="text-brand-teal font-medium hover:underline">
            Go to QR Studio &rarr;
          </Link>
        </div>
      )}

      {/* QR Code Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredCodes.map((qr) => (
          <div key={qr.id} className="bg-white rounded-xl border border-slate-200 shadow-sm hover:shadow-md transition-shadow p-5 flex flex-col">
            
            {/* Top: Name & Status */}
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="font-semibold text-brand-navy truncate">{qr.name}</h3>
                <span className="inline-flex items-center gap-1 mt-1 px-2 py-0.5 bg-slate-100 text-slate-600 text-xs font-medium rounded-full">
                  {qr.code_mode === 'dynamic' ? 'Dynamic' : 'Static'}
                </span>
              </div>
              <span className={`px-2.5 py-1 rounded-full text-xs font-medium ${
                qr.status === 'active' ? 'bg-green-50 text-green-700' : 
                qr.status === 'paused' ? 'bg-yellow-50 text-yellow-700' : 
                'bg-red-50 text-red-700'
              }`}>
                {qr.status.charAt(0).toUpperCase() + qr.status.slice(1)}
              </span>
            </div>

            {/* Middle: Destination */}
            <div className="mb-4 flex-1">
              <p className="text-xs text-slate-500 mb-1">Destination:</p>
              <a 
                href={qr.current_destination} 
                target="_blank" 
                rel="noreferrer"
                className="text-sm text-brand-teal hover:underline flex items-center gap-1 truncate"
              >
                {qr.current_destination}
                <ExternalLink className="w-3 h-3 flex-shrink-0" />
              </a>
            </div>

            {/* Bottom: Stats */}
            <div className="text-xs text-slate-500 flex items-center gap-2 mb-4">
              <Calendar className="w-3.5 h-3.5" />
              Created {new Date(qr.created_at).toLocaleDateString()}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2 pt-4 border-t border-slate-100">
              <button
                onClick={() => handleDownload(qr.id, qr.name)}
                className="flex-1 flex items-center justify-center gap-2 py-2 bg-slate-50 hover:bg-slate-100 text-slate-700 text-sm font-medium rounded-lg transition-colors"
                title="Download PNG"
              >
                <Download className="w-4 h-4" />
                Download
              </button>
              
              <button
                onClick={() => handleToggleStatus(qr.id, qr.status)}
                className={`p-2 rounded-lg transition-colors ${
                  qr.status === 'active' 
                    ? 'text-yellow-600 bg-yellow-50 hover:bg-yellow-100' 
                    : 'text-green-600 bg-green-50 hover:bg-green-100'
                }`}
                title={qr.status === 'active' ? 'Pause' : 'Activate'}
              >
                {qr.status === 'active' ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
              </button>
            </div>

          </div>
        ))}
      </div>
    </div>
  );
}