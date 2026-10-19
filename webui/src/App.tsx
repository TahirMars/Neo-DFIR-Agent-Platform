import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { applyTheme, getStoredTheme } from './stores/theme'
import { DialogProvider } from './components/DialogProvider'
import { Layout } from './components/Layout'
import { ProtectedRoute } from './components/ProtectedRoute'
import { Login } from './views/Login'
import { Home } from './views/Home'
import { CaseList } from './views/CaseList'
import { SessionList } from './views/SessionList'
import { SessionDetail } from './views/SessionDetail'
import { ReportListView } from './views/ReportListView'
import { ReportPreviewView } from './views/ReportPreviewView'
import { MyReportsView } from './views/MyReportsView'
import { UserCasesView } from './views/UserCasesView'
import './App.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

function ThemeSync() {
  const location = useLocation()
  useEffect(() => {
    if (location.pathname === '/login') {
      applyTheme('dark')
    } else {
      applyTheme(getStoredTheme())
    }
  }, [location.pathname])
  return null
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ThemeSync />
        <DialogProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Home />} />
            <Route path="cases" element={<CaseList />} />
            <Route path="cases/:caseId/sessions" element={<SessionList />} />
            <Route path="cases/:caseId/sessions/:sessionId" element={<SessionDetail />} />
            <Route path="cases/:caseId/sessions/:sessionId/reports" element={<ReportListView />} />
            <Route path="cases/:caseId/sessions/:sessionId/reports/:reportId" element={<ReportPreviewView />} />
            <Route path="cases/:caseId/sessions/:sessionId/report" element={<Navigate to="reports" replace />} />
            <Route path="reports" element={<MyReportsView />} />
            <Route path="admin/users/:userId/cases" element={<UserCasesView />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
        </DialogProvider>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
