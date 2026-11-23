import { useLocation, Link } from 'react-router-dom';
import { Shield, ArrowLeft, FileText } from 'lucide-react';

export default function LegalPage() {
  const location = useLocation();
  const path = location.pathname;

  const content = {
    '/privacy': {
      title: 'Privacy Policy',
      lastUpdated: 'November 2026',
      icon: Shield,
      body: (
        <>
          <p className="mb-6 text-lg text-slate-600 leading-relaxed">At ScanSentry, we take your privacy seriously. This policy explains how we collect, use, and protect your data.</p>
          <h3 className="text-xl font-bold mt-10 mb-4 text-brand-navy">1. Information We Collect</h3>
          <p className="mb-4 text-slate-600 leading-relaxed">We collect the email address and display name you provide during registration. For QR code owners, we track scan analytics (device type, broad region) but do not retain raw IP addresses.</p>
          <h3 className="text-xl font-bold mt-10 mb-4 text-brand-navy">2. How We Use Your Data</h3>
          <p className="mb-4 text-slate-600 leading-relaxed">Your data is used to operate your account, generate secure QR codes, and provide domain intelligence assessments. We do not sell your personal data to third parties.</p>
          <h3 className="text-xl font-bold mt-10 mb-4 text-brand-navy">3. Data Retention</h3>
          <p className="mb-4 text-slate-600 leading-relaxed">We retain your account information until you request deletion. You can request account deletion from your dashboard settings.</p>
        </>
      )
    },
    '/terms': {
      title: 'Terms of Service',
      lastUpdated: 'November 2026',
      icon: FileText,
      body: (
        <>
          <p className="mb-6 text-lg text-slate-600 leading-relaxed">By using ScanSentry, you agree to these terms.</p>
          <h3 className="text-xl font-bold mt-10 mb-4 text-brand-navy">1. Acceptable Use</h3>
          <p className="mb-4 text-slate-600 leading-relaxed">You may not use ScanSentry to generate QR codes that lead to phishing websites, malware, or fraudulent payment pages. We reserve the right to suspend accounts that violate this rule.</p>
          <h3 className="text-xl font-bold mt-10 mb-4 text-brand-navy">2. Security Assessments</h3>
          <p className="mb-4 text-slate-600 leading-relaxed">ScanSentry provides domain intelligence and security assessments as a tool. We do not guarantee that every threat will be detected. Never label a website as "100% safe" based solely on our assessment.</p>
          <h3 className="text-xl font-bold mt-10 mb-4 text-brand-navy">3. Subscriptions</h3>
          <p className="mb-4 text-slate-600 leading-relaxed">Some features require a paid subscription. Subscription terms and entitlements are managed via your dashboard.</p>
        </>
      )
    },
    '/contact': {
      title: 'Contact Us',
      lastUpdated: 'We usually respond within 24 hours.',
      icon: Shield,
      body: (
        <>
          <p className="mb-6 text-lg text-slate-600 leading-relaxed">Have a question about ScanSentry? Need to report a suspicious QR code? Reach out to our team.</p>
          <div className="mt-8 p-8 bg-slate-50 rounded-2xl border border-slate-200 hover:border-brand-teal transition-colors">
            <p className="font-bold text-brand-navy text-lg mb-2">Email Support</p>
            <a href="mailto:support@scansentry.com" className="text-brand-teal text-lg hover:underline font-medium">support@scansentry.com</a>
          </div>
          <div className="mt-4 p-8 bg-slate-50 rounded-2xl border border-slate-200 hover:border-brand-teal transition-colors">
            <p className="font-bold text-brand-navy text-lg mb-2">Report Abuse</p>
            <p className="text-slate-600 mb-3">Found a malicious QR code generated with ScanSentry?</p>
            <Link to="/dashboard" className="inline-flex items-center gap-2 text-brand-teal font-medium hover:underline">
              Log in to report it from your dashboard &rarr;
            </Link>
          </div>
        </>
      )
    }
  };

  const pageContent = content[path as keyof typeof content] || content['/privacy'];
  const PageIcon = pageContent.icon;

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      
      {/* NAVBAR */}
      <nav className="bg-brand-navy py-4 shadow-md relative z-20">
        <div className="max-w-5xl mx-auto px-6 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 text-white hover:opacity-80 transition">
            <Shield className="w-6 h-6 text-brand-teal" />
            <span className="text-xl font-bold tracking-tight">ScanSentry</span>
          </Link>
          <Link to="/" className="text-sm font-medium text-slate-300 hover:text-white flex items-center gap-2 bg-white/5 px-4 py-2 rounded-lg transition">
            <ArrowLeft className="w-4 h-4" /> Back to Home
          </Link>
        </div>
      </nav>

      {/* HERO HEADER */}
      <div className="bg-brand-navy pt-12 pb-32 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-brand-teal/10 rounded-full blur-3xl"></div>
        <div className="max-w-5xl mx-auto px-6 relative z-10">
          <div className="flex items-center gap-4 mb-4">
            <div className="w-12 h-12 rounded-xl bg-brand-teal/20 flex items-center justify-center text-brand-teal border border-brand-teal/30">
              <PageIcon className="w-6 h-6" />
            </div>
            <h1 className="text-3xl md:text-4xl font-bold text-white">{pageContent.title}</h1>
          </div>
          <p className="text-slate-400">Last updated: {pageContent.lastUpdated}</p>
        </div>
      </div>

      {/* FLOATING CONTENT CARD */}
      <div className="max-w-3xl mx-auto px-6 w-full -mt-20 relative z-20 mb-20">
        <div className="bg-white p-8 md:p-12 rounded-3xl shadow-xl border border-slate-100">
          {pageContent.body}
        </div>
      </div>

      {/* FOOTER */}
      <footer className="border-t border-slate-200 py-8 bg-white mt-auto">
        <div className="max-w-5xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-4 text-sm text-slate-500">
          <p>© 2026 ScanSentry. All rights reserved.</p>
          <div className="flex gap-6">
            <Link to="/privacy" className="hover:text-brand-navy transition">Privacy</Link>
            <Link to="/terms" className="hover:text-brand-navy transition">Terms</Link>
            <Link to="/contact" className="hover:text-brand-navy transition">Contact</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}