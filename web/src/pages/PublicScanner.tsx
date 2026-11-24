import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { Html5QrcodeScanner, Html5Qrcode } from 'html5-qrcode';
import { Shield, ShieldAlert, ShieldCheck, Upload, Camera, ArrowLeft, ExternalLink, RefreshCw, AlertTriangle } from 'lucide-react';
import api from '../services/api';

export default function PublicScanner() {
  const [scanResult, setScanResult] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<any>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const [mode, setMode] = useState<'camera' | 'upload'>('camera');
  
  const scannerRef = useRef<Html5QrcodeScanner | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (mode === 'camera' && !scanResult) {
      const scanner = new Html5QrcodeScanner(
        "reader",
        { fps: 10, qrbox: { width: 250, height: 250 } },
        false
      );
      
      scanner.render(
        (decodedText) => {
          scanner.clear();
          handleScan(decodedText);
        },
        () => {}
      );
      
      scannerRef.current = scanner;
    }

    return () => {
      if (scannerRef.current) {
        scannerRef.current.clear().catch(() => {});
      }
    };
  }, [mode, scanResult]);

  const handleScan = async (decodedText: string) => {
    setScanResult(decodedText);
    setIsAnalyzing(true);
    setError('');

    try {
      const response = await api.post('/scanner/analyze/', {
        content: decodedText,
        assess: true, 
        scanner_type: mode
      });
      
      console.log("BACKEND SCANNER RESPONSE:", response.data);
      setAnalysis(response.data);
    } catch (err: any) {
      console.error(err);
      setError('Failed to analyze the QR code. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const html5QrCode = new Html5Qrcode("reader-hidden");
      const decodedText = await html5QrCode.scanFile(file, true);
      handleScan(decodedText);
    } catch (err) {
      setError('Could not find a valid QR code in that image.');
    }
  };

  const resetScanner = () => {
    setScanResult(null);
    setAnalysis(null);
    setError('');
    setMode('camera');
  };

  // Helper to determine risk colors based on her backend's response
  const getRiskLevel = () => {
    if (!analysis?.security) return 'unknown';
    const status = analysis.security.status;
    const score = analysis.security.risk_score || 0;
    
    if (status === 'malicious' || score > 70) return 'malicious';
    if (status === 'suspicious' || status === 'needs_further_verification') return 'suspicious';
    return 'clean';
  };

  const riskLevel = getRiskLevel();

  return (
    <div className="min-h-screen bg-brand-navy text-white font-sans">
      <nav className="border-b border-white/10 bg-brand-navy/80 backdrop-blur-md">
        <div className="max-w-4xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-brand-teal" />
            <span className="text-xl font-bold">ScanSentry</span>
          </Link>
          <Link to="/" className="text-sm text-slate-400 hover:text-white flex items-center gap-2">
            <ArrowLeft className="w-4 h-4" /> Back to Home
          </Link>
        </div>
      </nav>

      <div className="max-w-2xl mx-auto px-6 py-12">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold mb-2">QR Code Scanner</h1>
          <p className="text-slate-400">Scan a code to check if it's safe before you visit.</p>
        </div>

        {!scanResult ? (
          <div className="bg-brand-charcoal rounded-2xl border border-white/10 overflow-hidden shadow-2xl">
            <div className="flex border-b border-white/10">
              <button 
                onClick={() => setMode('camera')}
                className={`flex-1 py-4 flex items-center justify-center gap-2 text-sm font-medium ${mode === 'camera' ? 'bg-brand-teal text-white' : 'text-slate-400 hover:text-white'}`}
              >
                <Camera className="w-4 h-4" /> Use Camera
              </button>
              <button 
                onClick={() => setMode('upload')}
                className={`flex-1 py-4 flex items-center justify-center gap-2 text-sm font-medium ${mode === 'upload' ? 'bg-brand-teal text-white' : 'text-slate-400 hover:text-white'}`}
              >
                <Upload className="w-4 h-4" /> Upload Image
              </button>
            </div>

            <div className="p-6">
              {mode === 'camera' ? (
                <div className="text-center">
                  <div id="reader" className="w-full rounded-xl overflow-hidden bg-black"></div>
                  <p className="text-xs text-slate-500 mt-4">Point your camera at a QR code</p>
                </div>
              ) : (
                <div className="text-center py-12">
                  <div id="reader-hidden" className="hidden"></div>
                  <input 
                    type="file" 
                    accept="image/*" 
                    ref={fileInputRef}
                    onChange={handleFileUpload}
                    className="hidden" 
                  />
                  <div className="w-20 h-20 bg-white/5 rounded-full flex items-center justify-center mx-auto mb-4">
                    <Upload className="w-8 h-8 text-slate-400" />
                  </div>
                  <button 
                    onClick={() => fileInputRef.current?.click()}
                    className="px-6 py-3 bg-brand-teal hover:bg-teal-600 text-white font-medium rounded-lg transition-colors"
                  >
                    Choose an Image
                  </button>
                  <p className="text-xs text-slate-500 mt-4">Upload a screenshot containing a QR code</p>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="bg-brand-charcoal rounded-2xl border border-white/10 p-6 shadow-2xl">
              <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Decoded Content</h3>
              <div className="bg-black/50 p-4 rounded-lg font-mono text-sm text-brand-teal break-all">
                {scanResult}
              </div>
            </div>

            {isAnalyzing ? (
              <div className="bg-brand-charcoal rounded-2xl border border-white/10 p-12 text-center">
                <RefreshCw className="w-8 h-8 text-brand-teal animate-spin mx-auto mb-4" />
                <p className="text-slate-300">Running security analysis...</p>
                <p className="text-xs text-slate-500 mt-2">Checking domain age, SSL, and threat databases</p>
              </div>
            ) : error ? (
              <div className="bg-red-500/10 border border-red-500/30 rounded-2xl p-6 text-center">
                <ShieldAlert className="w-10 h-10 text-red-400 mx-auto mb-3" />
                <h3 className="text-lg font-bold text-red-400">Analysis Failed</h3>
                <p className="text-sm text-slate-300 mt-1">{error}</p>
              </div>
            ) : analysis ? (
              <div className="bg-brand-charcoal rounded-2xl border border-white/10 p-6 shadow-2xl">
                <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Security Assessment</h3>
                
                {/* RISK BANNER */}
                <div className={`p-4 rounded-xl border mb-6 flex items-start gap-3 ${
                  riskLevel === 'malicious' ? 'bg-red-500/10 border-red-500/30' :
                  riskLevel === 'suspicious' ? 'bg-amber-500/10 border-amber-500/30' :
                  'bg-green-500/10 border-green-500/30'
                }`}>
                  {riskLevel === 'malicious' ? <ShieldAlert className="w-6 h-6 text-red-400 flex-shrink-0" /> :
                   riskLevel === 'suspicious' ? <ShieldAlert className="w-6 h-6 text-amber-400 flex-shrink-0" /> :
                   <ShieldCheck className="w-6 h-6 text-green-400 flex-shrink-0" />}
                  
                  <div>
                    <h4 className={`font-bold capitalize ${
                      riskLevel === 'malicious' ? 'text-red-400' :
                      riskLevel === 'suspicious' ? 'text-amber-400' :
                      'text-green-400'
                    }`}>
                      {analysis.security?.label || riskLevel}
                    </h4>
                    <p className="text-sm text-slate-300 mt-1">
                      {analysis.security?.summary || 'Analysis complete.'}
                    </p>
                    {analysis.security?.confidence && (
                      <p className="text-xs text-slate-500 mt-2">Confidence: {analysis.security.confidence}</p>
                    )}
                  </div>
                </div>

                {/* FINDINGS */}
                {analysis.security?.top_findings && analysis.security.top_findings.length > 0 && (
                  <div className="mb-6">
                    <h4 className="text-sm font-semibold text-slate-400 mb-2">Findings</h4>
                    <ul className="space-y-2">
                      {analysis.security.top_findings.map((finding: any, idx: number) => (
                        <li key={idx} className="flex items-start gap-2 text-sm text-slate-300 bg-white/5 p-3 rounded-lg">
                          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                          <div>
                            <span className="font-medium text-white">{finding.name}:</span> {finding.message}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* MISSING CHECKS */}
                {analysis.security?.missing_checks && analysis.security.missing_checks.length > 0 && (
                  <div className="mb-6 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-start gap-2 text-sm text-amber-200">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                    <p>Could not complete: {analysis.security.missing_checks.join(', ')}</p>
                  </div>
                )}

                {/* DESTINATION LINK */}
                {analysis.url?.normalized && (
                  <a 
                    href={analysis.url.normalized} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="w-full py-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg flex items-center justify-center gap-2 text-sm font-medium transition-colors"
                  >
                    Proceed to Destination <ExternalLink className="w-4 h-4" />
                  </a>
                )}
              </div>
            ) : null}

            <button 
              onClick={resetScanner}
              className="w-full py-3 bg-brand-teal hover:bg-teal-600 text-white font-bold rounded-lg transition-colors"
            >
              Scan Another Code
            </button>
          </div>
        )}
      </div>
    </div>
  );
}