import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './context/AuthContext';
import Login from './pages/Login';

const queryClient = new QueryClient();

// We will build the real dashboard later. For now, just a simple placeholder.
function DashboardPlaceholder() {
  return (
    <div className="min-h-screen bg-slate-50 flex flex-col items-center justify-center">
      <h1 className="text-3xl font-bold text-brand-navy mb-4">Dashboard Coming Soon!</h1>
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/dashboard" element={<DashboardPlaceholder />} />
            <Route path="/" element={<Navigate to="/login" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}