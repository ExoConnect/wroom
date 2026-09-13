import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { Toaster } from '@/components/ui/sonner'
import { useMediaQuery } from '@/hooks/useMediaQuery'
import { useCallStore } from '@/store/call'

// ui/sonner resolves its theme through next-themes, which we don't use —
// pass our own resolved store theme so toasts match the app.
export function ThemedToaster() {
  const theme = useCallStore((s) => s.theme)
  const systemDark = useMediaQuery('(prefers-color-scheme: dark)')
  const resolved = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme
  return <Toaster richColors position="top-center" theme={resolved} />
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
    <ThemedToaster />
  </StrictMode>,
)
