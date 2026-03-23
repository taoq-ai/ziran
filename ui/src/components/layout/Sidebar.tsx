import { BookOpen, LayoutDashboard, Plus, Settings } from "lucide-react"
import { NavLink } from "react-router-dom"
import { cn } from "../../lib/utils"

const links = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/runs/new", label: "New Run", icon: Plus },
  { to: "/library", label: "Library", icon: BookOpen },
  { to: "/settings", label: "Settings", icon: Settings },
]

export function Sidebar() {
  return (
    <aside className="w-56 border-r border-border bg-bg-secondary flex flex-col">
      <div className="px-4 py-5 border-b border-border">
        <h1 className="text-lg font-bold tracking-tight text-accent">ZIRAN</h1>
        <p className="text-xs text-text-muted">AI Agent Security</p>
      </div>
      <nav className="flex-1 px-2 py-3 space-y-1">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                isActive
                  ? "bg-accent/10 text-accent"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-card"
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}
