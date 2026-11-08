import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, AlertCircle } from 'lucide-react';
import { useAuth } from "../context/AuthContext";
import api from '../services/api';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      
      const response = await api.post('/auth/login/', { email, password });
      
      
      login({ 
        access: response.data.access, 
        refresh: response.data.refresh 
      });
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Invalid email or password. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex bg-brand-navy">
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 bg-brand-navy relative overflow-hidden">
        <div className="relative z-10">
          <div className="flex items-center gap-3 text-white mb-8">
            <Shield className="w-10 h-10 text-brand-teal" />
            <span className="text-3xl font-bold tracking-tight">ScanSentry</span>
          </div>
          <h1 className="text-5xl font-bold text-white leading-tight mb-6">
            Every scan <br />
            deserves <span className="text-brand-teal">protection.</span>
          </h1>
          <p className="text-slate-400 text-lg max-w-md">
            Create, verify, and monitor QR codes with enterprise-grade domain intelligence and threat detection.
          </p>
        </div>
        
        
        <div className="absolute -bottom-32 -left-32 w-96 h-96 bg-brand-teal/10 rounded-full blur-3xl"></div>
        <div className="absolute top-1/4 -right-32 w-96 h-96 bg-brand-cyan/10 rounded-full blur-3xl"></div>
        
        <div className="relative z-10 text-slate-500 text-sm">
          © 2026 ScanSentry. All rights reserved.
        </div>
      </div>

      <div className="w-full lg:w-1/2 flex items-center justify-center p-8 bg-slate-50">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-xl p-8 border border-slate-100">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-bold text-brand-navy">Welcome back</h2>
            <p className="text-slate-500 mt-2">Log in to manage your QR codes</p>
          </div>

          {error && (
            <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3 text-red-700 text-sm">
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <p>{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Email Address</label>
              <div className="relative">
                <Mail className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-teal/50 focus:border-brand-teal transition"
                  placeholder="you@company.com"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-sm font-medium text-slate-700">Password</label>
                <Link to="/forgot-password" className="text-sm font-medium text-brand-teal hover:text-brand-cyan">
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <Lock className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-teal/50 focus:border-brand-teal transition"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 bg-brand-navy hover:bg-brand-charcoal text-white font-medium rounded-lg transition-colors disabled:opacity-70 flex justify-center items-center"
            >
              {isLoading ? 'Logging in...' : 'Log in'}
            </button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-8">
            Don't have an account?{' '}
            <Link to="/register" className="font-medium text-brand-teal hover:text-brand-cyan">
              Create one free
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}