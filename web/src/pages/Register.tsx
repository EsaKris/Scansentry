import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, User, AlertCircle, CheckCircle, Eye, EyeOff } from 'lucide-react';
import api from '../services/api';

export default function Register() {
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
 const [showPassword, setShowPassword] = useState(false);

  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Send registration request to Django backend
      await api.post('/auth/register/', { 
        email, 
        password, 
        display_name: displayName 
      });
      
      setSuccess(true);
      //  send to them to login at 2s
      setTimeout(() => navigate('/login'), 2000);
    } catch (err: any) {
      // Handle backend validation errors 
      const errorData = err.response?.data;
      if (errorData?.email) {
        setError(errorData.email[0]);
      } else if (errorData?.password) {
        setError(errorData.password[0]);
      } else {
        setError(errorData?.detail || 'Registration failed. Please check your details.');
      }
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
            Join the <br />
            <span className="text-brand-teal">security</span> network.
          </h1>
          <p className="text-slate-400 text-lg max-w-md">
            Create an account to generate secure dynamic QR codes and monitor who scans them.
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
            <h2 className="text-2xl font-bold text-brand-navy">Create an account</h2>
            <p className="text-slate-500 mt-2">Start protecting your QR codes today</p>
          </div>

          {error && (
            <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3 text-red-700 text-sm">
              <AlertCircle className="w-5 h-5 flex-shrink-0" />
              <p>{error}</p>
            </div>
          )}

          {success && (
            <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg flex items-start gap-3 text-green-700 text-sm">
              <CheckCircle className="w-5 h-5 flex-shrink-0" />
              <p>Account created successfully! Redirecting to login...</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Display Name</label>
              <div className="relative">
                <User className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-teal/50 focus:border-brand-teal transition"
                  placeholder="Your Name"
                />
              </div>
            </div>

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
                  placeholder="Your Email"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
              <div className="relative">
                <Lock className="w-5 h-5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type={showPassword ? "text" : "password"}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-teal/50 focus:border-brand-teal transition"
                  placeholder="••••••••"
                />

                {/* eye button */}
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 focus:outline-none"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>

              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading || success}
              className="w-full py-2.5 bg-brand-navy hover:bg-brand-charcoal text-white font-medium rounded-lg transition-colors disabled:opacity-70 flex justify-center items-center mt-2"
            >
              {isLoading ? 'Creating account...' : 'Create account'}
            </button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-8">
            Already have an account?{' '}
            <Link to="/login" className="font-medium text-brand-teal hover:text-brand-cyan">
              Log in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}



