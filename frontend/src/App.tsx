import { BrowserRouter, Routes, Route } from 'react-router'
import { Toaster } from 'sonner'
import SignInPage from './pages/SignInPage'
import SignUpPage from './pages/SignUpPage'
import ChatAppPage from './pages/ChatAppPage'
import ProtectedRoute from '@/components/auth/ProtectedRoute'

function App() {
  return (
    <>
      <Toaster richColors />
      <BrowserRouter>
        <Routes>
          {/* public routes */}
          <Route path="/signin" element={<SignInPage />} />
          <Route path="/signup" element={<SignUpPage />} />
          {/* protected routes */}
          <Route element={<ProtectedRoute />}>
            <Route path='/' element={<ChatAppPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </>
  )
}

export default App
