import { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Shield, QrCode, Globe, BarChart3, ShieldCheck, ShieldAlert, CheckCircle2, ArrowRight, Activity, Zap, Lock, EyeOff } from 'lucide-react';

export default function LandingPage() {
  
  // This useEffect adds the scroll animation magic
  useEffect(() => {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('active');
        }
      });
    }, { threshold: 0.1 });

    document.querySelectorAll('.reveal').forEach((el) => observer.observe(el));
    
    return () => observer.disconnect();
  }, []);

  return (
    <div className="min-h-screen bg-brand-navy text-white font-sans selection:bg-brand-teal selection:text-white overflow-x-hidden">
      
      {/* GLOBAL ANIMATION STYLES */}
      <style>{`
        @keyframes float {
          0% { transform: translateY(0px); }
          50% { transform: translateY(-15px); }
          100% { transform: translateY(0px); }
        }
        @keyframes scroll {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        .animate-marquee {
          animation: scroll 25s linear infinite;
        }
        .animate-float {
          animation: float 6s ease-in-out infinite;
        }
        /* Scroll Reveal */
        .reveal {
          opacity: 0;
          transform: translateY(40px);
          transition: all 0.8s cubic-bezier(0.5, 0, 0, 1);
        }
        .reveal.active {
          opacity: 1;
          transform: translateY(0);
        }
      `}</style>

      {/* NAVBAR */}
      <nav className="fixed w-full top-0 z-50 bg-brand-navy/80 backdrop-blur-md border-b border-white/10">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-brand-teal" />
            <span className="text-2xl font-bold tracking-tight">ScanSentry</span>
          </div>
          <div className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-300">
            <a href="#features" className="hover:text-white transition">Features</a>
            <a href="#how-it-works" className="hover:text-white transition">How it Works</a>
            <a href="#security" className="hover:text-white transition">Security</a>
          </div>
          <div className="flex items-center gap-4">
            <Link to="/login" className="text-sm font-medium text-slate-300 hover:text-white transition hidden sm:block">
              Log in
            </Link>
            <Link to="/register" className="px-5 py-2.5 bg-brand-teal hover:bg-teal-600 text-white text-sm font-bold rounded-lg transition-colors shadow-lg shadow-brand-teal/20">
              Get Started Free
            </Link>
          </div>
        </div>
      </nav>

      {/* HERO SECTION */}
      <section className="relative pt-32 pb-20 lg:pt-48 lg:pb-32 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[1000px] h-[500px] bg-brand-teal/20 rounded-full blur-[120px] pointer-events-none animate-pulse"></div>
        
        <div className="max-w-7xl mx-auto px-6 relative z-10 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/5 border border-white/10 text-brand-teal text-sm font-medium mb-6 reveal">
            <ShieldCheck className="w-4 h-4" />
            <span>The Cybersecurity-First QR Platform</span>
          </div>
          
          <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight mb-6 leading-tight reveal">
            Every scan <br className="hidden md:block" />
            deserves <span className="text-transparent bg-clip-text bg-gradient-to-r from-brand-teal to-brand-cyan">protection.</span>
          </h1>
          
          <p className="mt-4 text-xl text-slate-400 max-w-2xl mx-auto mb-10 reveal">
            Create, verify, and monitor dynamic QR codes. Protect your customers from phishing and malicious redirects with enterprise-grade domain intelligence.
          </p>
          
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 reveal">
            <Link to="/register" className="w-full sm:w-auto px-8 py-4 bg-brand-teal hover:bg-teal-600 text-white font-bold rounded-lg transition-all flex items-center justify-center gap-2 text-lg">
              Create a Secure QR <ArrowRight className="w-5 h-5" />
            </Link>
            <Link to="/scanner" className="w-full sm:w-auto px-8 py-4 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-bold rounded-lg transition-all flex items-center justify-center text-lg">
              Try the Scanner
            </Link>
          </div>

          {/* LIVE STATS BAR */}
          <div className="mt-16 flex flex-wrap justify-center gap-8 md:gap-16 border-y border-white/5 py-6 reveal">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-brand-teal" />
              <div className="text-left">
                <p className="text-xl font-bold text-white">1.2M+</p>
                <p className="text-xs text-slate-500 uppercase tracking-wider">Scans Verified</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <ShieldAlert className="w-5 h-5 text-brand-teal" />
              <div className="text-left">
                <p className="text-xl font-bold text-white">45K+</p>
                <p className="text-xs text-slate-500 uppercase tracking-wider">Threats Blocked</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Zap className="w-5 h-5 text-brand-teal" />
              <div className="text-left">
                <p className="text-xl font-bold text-white">99.9%</p>
                <p className="text-xs text-slate-500 uppercase tracking-wider">Uptime</p>
              </div>
            </div>
          </div>

          {/* MOVING LOGO MARQUEE */}
          <div className="mt-12 reveal">
            <p className="text-xs text-slate-500 font-semibold tracking-widest uppercase mb-8">Trusted by modern security teams</p>
            <div className="relative overflow-hidden w-full max-w-4xl mx-auto [mask-image:linear-gradient(to_right,transparent,black_10%,black_90%,transparent)]">
              <div className="flex w-max animate-marquee gap-16 items-center opacity-60 grayscale hover:grayscale-0 transition-all duration-500">
                {[1, 2].map((loop) => (
                  <div key={loop} className="flex gap-16 items-center">
                    <span className="text-2xl font-bold font-serif italic">Stripe</span>
                    <span className="text-2xl font-bold tracking-tighter">VERCEL</span>
                    <span className="text-2xl font-bold font-mono">Paystack</span>
                    <span className="text-2xl font-bold">Flutterwave</span>
                    <span className="text-2xl font-black uppercase">Access Bank</span>
                    <span className="text-2xl font-bold tracking-widest">MTN</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* THE PROBLEM SECTION (Upgraded) */}
      <section id="security" className="py-24 bg-brand-charcoal relative">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16 reveal">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">The danger is invisible.</h2>
            <p className="text-slate-400 text-lg max-w-2xl mx-auto">
              A malicious actor can replace a legitimate QR code with a fraudulent one in seconds. Don't let your users scan blindly.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8 items-center max-w-5xl mx-auto">
            
            {/* BLIND SCAN (Bad) */}
            <div className="bg-brand-navy p-8 rounded-2xl border border-white/10 relative reveal opacity-80">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center">
                    <EyeOff className="w-5 h-5 text-slate-400" />
                  </div>
                  <h3 className="text-lg font-semibold text-slate-300">Blind Scanning</h3>
                </div>
                <span className="px-2 py-1 bg-slate-800 text-slate-400 text-xs font-bold rounded">UNSAFE</span>
              </div>
              <div className="space-y-4">
                <div className="p-4 bg-slate-900 rounded-lg font-mono text-sm text-slate-400 border border-slate-800">
                  https://bit.ly/3xPh1sh
                </div>
                <p className="text-sm text-slate-500">User has no idea where the link leads. They could be entering their password into a fake website.</p>
              </div>
            </div>

            {/* SCANSENTRY SCAN (Good) */}
            <div className="bg-brand-navy p-8 rounded-2xl border-2 border-brand-teal relative reveal shadow-[0_0_30px_rgba(13,148,136,0.15)] animate-float">
              <div className="absolute -top-3 -right-3 bg-brand-teal text-white text-xs font-bold px-3 py-1 rounded-full shadow-lg flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5" /> PROTECTED
              </div>
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-full bg-brand-teal/20 flex items-center justify-center">
                  <Lock className="w-5 h-5 text-brand-teal" />
                </div>
                <h3 className="text-lg font-semibold text-white">ScanSentry Verified</h3>
              </div>
              <div className="space-y-4">
                <div className="p-4 bg-slate-900 rounded-lg text-sm border border-brand-teal/30">
                  <p className="text-xs text-slate-500 mb-1">Destination Verified</p>
                  <p className="font-mono text-brand-teal">https://mybusiness.com/menu</p>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <CheckCircle2 className="w-4 h-4 text-green-400" /> Domain Registered: 5 years ago
                  <br />
                  <CheckCircle2 className="w-4 h-4 text-green-400" /> SSL Certificate Valid
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section id="how-it-works" className="py-24 overflow-hidden">
        <div className="max-w-7xl mx-auto px-6 text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-4 reveal">How ScanSentry works</h2>
          <p className="text-slate-400 mb-16 max-w-2xl mx-auto reveal">Three steps to secure your QR ecosystem.</p>
          
          <div className="grid md:grid-cols-3 gap-8">
            {[
              { step: '01', title: 'Create', desc: 'Generate dynamic QR codes with custom colors, logos, and secure redirect tokens.', icon: QrCode },
              { step: '02', title: 'Verify', desc: 'Every scan passes through our domain intelligence engine to check for threats.', icon: ShieldCheck },
              { step: '03', title: 'Monitor', desc: 'Track scan analytics, view destination history, and receive real-time security alerts.', icon: BarChart3 },
            ].map((item, i) => (
              <div key={i} className="bg-white/5 border border-white/10 p-8 rounded-2xl text-left hover:bg-white/10 transition-all duration-300 hover:-translate-y-2 reveal" style={{ transitionDelay: `${i * 150}ms` }}>
                <div className="text-brand-teal font-mono text-sm mb-4">{item.step}</div>
                <item.icon className="w-10 h-10 text-white mb-6" />
                <h3 className="text-xl font-bold mb-2">{item.title}</h3>
                <p className="text-slate-400 text-sm">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FEATURES GRID */}
      <section id="features" className="py-24 bg-brand-charcoal overflow-hidden">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16 reveal">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Everything you need to secure your QR codes</h2>
          </div>
          
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              { title: 'Dynamic QR Codes', desc: 'Change the destination URL anytime without reprinting.', icon: QrCode },
              { title: 'Domain Intelligence', desc: 'RDAP, DNS, and SSL checks for every destination.', icon: Globe },
              { title: 'Threat Detection', desc: 'Rule-based engine and threat intelligence integration.', icon: ShieldAlert },
              { title: 'Real-time Analytics', desc: 'Know exactly when, where, and how often your codes are scanned.', icon: BarChart3 },
            ].map((feature, i) => (
              <div key={i} className="bg-brand-navy p-6 rounded-xl border border-white/5 hover:border-brand-teal/50 transition-colors duration-300 reveal" style={{ transitionDelay: `${i * 100}ms` }}>
                <feature.icon className="w-8 h-8 text-brand-teal mb-4" />
                <h3 className="text-lg font-bold mb-2">{feature.title}</h3>
                <p className="text-slate-400 text-sm">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA SECTION */}
      <section className="py-24 relative overflow-hidden">
        <div className="absolute inset-0 bg-brand-teal/10 reveal"></div>
        <div className="max-w-4xl mx-auto px-6 relative z-10 text-center reveal">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">Start protecting your audience today.</h2>
          <p className="text-xl text-slate-300 mb-10">Join the platform that treats QR security as a priority, not an afterthought.</p>
          <Link to="/register" className="inline-flex items-center gap-2 px-8 py-4 bg-brand-teal hover:bg-teal-600 text-white font-bold rounded-lg transition-all text-lg shadow-xl shadow-brand-teal/20 hover:scale-105">
            Create Free Account <CheckCircle2 className="w-6 h-6" />
          </Link>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="border-t border-white/10 py-12 bg-brand-navy">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-brand-teal" />
            <span className="text-xl font-bold">ScanSentry</span>
          </div>
          <div className="flex gap-6 text-sm text-slate-400">
            <Link to="/privacy" className="hover:text-white">
              Privacy Policy
            </Link>
            <Link to="/terms" className="hover:text-white">
              Terms of Service
            </Link>
            <Link to="/contact" className="hover:text-white">
              Contact
            </Link>
          </div>
          <p className="text-sm text-slate-500">© 2026 ScanSentry. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}
