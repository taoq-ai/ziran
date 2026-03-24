import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { lazy, Suspense, useEffect } from "react"
import { BrowserRouter, Route, Routes } from "react-router-dom"
import { Layout } from "./components/layout/Layout"
import { Dashboard } from "./pages/Dashboard"
import { Library } from "./pages/Library"
import { NewRun } from "./pages/NewRun"
import { RunDetail } from "./pages/RunDetail"
import { Settings } from "./pages/Settings"

const Findings = lazy(() => import("./pages/Findings"))
const Compliance = lazy(() => import("./pages/Compliance"))

const queryClient = new QueryClient()

export default function App() {
  useEffect(() => {
    const saved = localStorage.getItem("theme")
    if (!saved) {
      document.documentElement.classList.add("dark")
    }
  }, [])

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/runs/new" element={<NewRun />} />
            <Route path="/runs/:id" element={<RunDetail />} />
            <Route
              path="/findings"
              element={
                <Suspense fallback={<div className="text-center text-fg-secondary py-10">Loading...</div>}>
                  <Findings />
                </Suspense>
              }
            />
            <Route
              path="/compliance"
              element={
                <Suspense fallback={<div className="text-center text-fg-secondary py-10">Loading...</div>}>
                  <Compliance />
                </Suspense>
              }
            />
            <Route path="/library" element={<Library />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
