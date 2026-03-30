import { Home } from "lucide-react"
import { Link } from "react-router-dom"

export function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <p className="text-6xl font-bold text-fg-secondary mb-4">404</p>
      <h2 className="text-xl font-medium text-fg-primary mb-2">Page not found</h2>
      <p className="text-sm text-fg-secondary mb-6">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <Link
        to="/"
        className="inline-flex items-center gap-2 rounded-lg bg-accent text-bg-primary px-4 py-2 text-sm font-medium hover:bg-accent-hover transition-colors"
      >
        <Home className="h-4 w-4" />
        Back to Dashboard
      </Link>
    </div>
  )
}
