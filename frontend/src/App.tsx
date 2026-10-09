import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { WebSocketProvider } from './context/WebSocketContext';

import { LoginPage } from './pages/LoginPage';
import { AppLayout } from './components/layout/AppLayout';
import { DashboardPage } from './pages/DashboardPage';
import { EmailListPage } from './pages/EmailListPage';
import { EmailDetailPage } from './pages/EmailDetailPage';
import { EmailComparePage } from './pages/EmailComparePage';
import { CaseListPage } from './pages/CaseListPage';
import { CaseDetailPage } from './pages/CaseDetailPage';
import { RelationshipsPage } from './pages/RelationshipsPage';
import { IOCSearchPage } from './pages/IOCSearchPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { ReportsPage } from './pages/ReportsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { SettingsPage } from './pages/SettingsPage';

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) {
    return <div className="min-h-screen bg-soc-dark flex items-center justify-center font-mono text-xs text-slate-400">Authenticating...</div>;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <WebSocketProvider>
        <Router>
          <Routes>
            <Route path="/login" element={<LoginPage />} />

            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<DashboardPage />} />
              <Route path="emails" element={<EmailListPage />} />
              <Route path="emails/:id" element={<EmailDetailPage />} />
              <Route path="emails/compare" element={<EmailComparePage />} />
              <Route path="cases" element={<CaseListPage />} />
              <Route path="cases/:id" element={<CaseDetailPage />} />
              <Route path="relationships" element={<RelationshipsPage />} />
              <Route path="iocs" element={<IOCSearchPage />} />
              <Route path="threat-intel" element={<ThreatIntelPage />} />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="audit" element={<AuditLogsPage />} />
              <Route path="settings" element={<SettingsPage />} />
            </Route>
          </Routes>
        </Router>
      </WebSocketProvider>
    </AuthProvider>
  );
};

export default App;
