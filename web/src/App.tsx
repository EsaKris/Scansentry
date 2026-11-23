import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './context/AuthContext';

import Login from './pages/Login';
import Register from './pages/Register';
import DashboardLayout from './layouts/DashboardLayout';
import Dashboard from './pages/Dashboard';
import QRStudio from './pages/QRStudio';
import QRLibrary from './pages/QRLibrary';
import DomainIntel from './pages/DomainIntel';
import LandingPage from './pages/LandingPage';
import LegalPage from './pages/LegalPage';
import PublicScanner from './pages/PublicScanner';

const queryClient = new QueryClient();

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            {/* Public Routes */}
            <Route path="/" element={<LandingPage />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/scanner" element={<PublicScanner />} />

            {/* Legal Routes */}
            <Route path="/privacy" element={<LegalPage />} />
            <Route path="/terms" element={<LegalPage />} />
            <Route path="/contact" element={<LegalPage />} />

            {/* Protected Dashboard Routes */}
            <Route element={<DashboardLayout />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/studio" element={<QRStudio />} />
              <Route path="/library" element={<QRLibrary />} />
              <Route path="/domain-intel" element={<DomainIntel />} />

              
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}