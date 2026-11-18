import { useState } from 'react';
import { QrCode, Link as LinkIcon, Palette, Save, AlertCircle } from 'lucide-react';
import api from '../services/api';

export default function QRStudio() {
  const [name, setName] = useState('');
  const [destination, setDestination] = useState('');
  const [fgColor, setFgColor] = useState('#0F172A');
  const [bgColor, setBgColor] = useState('#FFFFFF');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);

  // Generate the preview
  const handlePreview = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await api.post('/qr/preview/', {
        qr_type: 'url',
        code_mode: 'dynamic', // We want dynamic so the destination can be changed later
        data: { url: destination },
        style: {
          fg_color: fgColor,
          bg_color: bgColor,
          error_correction: 'M',
          box_size: 10,
        }
      }, {
        responseType: 'blob' // Tell Axios the response is an image, not JSON
      });

      // Create a local URL for the image blob
      const imageUrl = URL.createObjectURL(response.data);
      setPreviewUrl(imageUrl);
    } catch (err: any) {
      setError('Failed to generate preview. Please check the URL.');
    } finally {
      setIsLoading(false);
    }
  };

    // Save the actual QR code
  const handleSave = async () => {
    if (!previewUrl) return;
    setIsLoading(true);
    setError('');

    try {
      console.log("Saving QR with data:", {
        name: name,
        qr_type: 'url',
        code_mode: 'dynamic',
        data: { url: destination },
        style: {
          fg_color: fgColor,
          bg_color: bgColor,
          error_correction: 'M',
          box_size: 10,
        }
      });

      await api.post('/qr/', {
        name: name,
        qr_type: 'url',
        code_mode: 'dynamic',
        data: { url: destination },
        style: {
          fg_color: fgColor,
          bg_color: bgColor,
          error_correction: 'M',
          box_size: 10,
        }
      });
      
      alert('QR Code saved successfully!');
      setPreviewUrl(null);
      setName('');
      setDestination('');
    } catch (err: any) {
      console.error("Save Error:", err.response?.data);
      // Show the actual error from her backend
      const errorMsg = err.response?.data ? JSON.stringify(err.response.data) : 'Failed to save.';
      setError(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <div className="max-w-4xl mx-auto">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-brand-navy">QR Studio</h1>
        <p className="text-slate-500">Generate a secure, dynamic QR code for your business.</p>
      </div>

      {error && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3 text-red-700 text-sm">
          <AlertCircle className="w-5 h-5 flex-shrink-0" />
          <p>{error}</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* LEFT: FORM */}
        <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
          <form onSubmit={handlePreview} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">QR Code Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-teal/50 focus:border-brand-teal transition"
                placeholder="e.g. My Restaurant Menu"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Destination URL</label>
              <div className="relative">
                <LinkIcon className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="url"
                  required
                  value={destination}
                  onChange={(e) => setDestination(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-teal/50 focus:border-brand-teal transition"
                  placeholder="https://example.com"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Foreground Color</label>
                <div className="flex items-center gap-2">
                  <input
                    type="color"
                    value={fgColor}
                    onChange={(e) => setFgColor(e.target.value)}
                    className="w-10 h-10 rounded cursor-pointer border-0 p-0"
                  />
                  <span className="text-sm text-slate-500 font-mono">{fgColor}</span>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Background Color</label>
                <div className="flex items-center gap-2">
                  <input
                    type="color"
                    value={bgColor}
                    onChange={(e) => setBgColor(e.target.value)}
                    className="w-10 h-10 rounded cursor-pointer border-0 p-0"
                  />
                  <span className="text-sm text-slate-500 font-mono">{bgColor}</span>
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 bg-brand-teal hover:bg-teal-600 text-white font-medium rounded-lg transition-colors flex justify-center items-center gap-2"
            >
              <Palette className="w-5 h-5" />
              {isLoading ? 'Generating...' : 'Generate Preview'}
            </button>
          </form>
        </div>

        {/* RIGHT: PREVIEW */}
        <div className="bg-slate-100 p-6 rounded-xl border border-slate-200 flex flex-col items-center justify-center min-h-[400px]">
          {previewUrl ? (
            <div className="text-center w-full">
              <img src={previewUrl} alt="QR Preview" className="w-64 h-64 mx-auto rounded-lg shadow-md bg-white p-2 mb-6" />
              <button
                onClick={handleSave}
                disabled={isLoading}
                className="w-full py-2.5 bg-brand-navy hover:bg-brand-charcoal text-white font-medium rounded-lg transition-colors flex justify-center items-center gap-2"
              >
                <Save className="w-5 h-5" />
                {isLoading ? 'Saving...' : 'Save to Dashboard'}
              </button>
            </div>
          ) : (
            <div className="text-center text-slate-400">
              <QrCode className="w-16 h-16 mx-auto mb-4 opacity-50" />
              <p>Your QR code preview will appear here</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
