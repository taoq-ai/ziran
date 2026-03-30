import { useState } from "react"
import {
  AlertTriangle,
  BookOpen,
  LayoutDashboard,
  Menu,
  Plus,
  Settings,
  Shield,
  ShieldCheck,
  X,
} from "lucide-react"
import { NavLink } from "react-router-dom"
import { cn } from "../../lib/utils"
import { ThemeToggle } from "./ThemeToggle"

const links = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/runs/new", label: "New Run", icon: Plus },
  { to: "/findings", label: "Findings", icon: AlertTriangle },
  { to: "/compliance", label: "Compliance", icon: ShieldCheck },
  { to: "/library", label: "Library", icon: BookOpen },
  { to: "/settings", label: "Settings", icon: Settings },
]

export function Sidebar() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <>
      {/* Mobile hamburger button */}
      <button
        onClick={() => setMobileOpen(true)}
        className="md:hidden fixed top-3 left-3 z-50 p-2 rounded-lg bg-bg-secondary border border-border"
      >
        <Menu className="h-5 w-5 text-fg-primary" />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="md:hidden fixed inset-0 z-40 bg-black/50"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "w-56 border-r border-border bg-bg-secondary flex flex-col",
          "fixed md:relative inset-y-0 left-0 z-50",
          "transition-transform duration-200 ease-in-out",
          mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
      >
        <div className="px-4 py-5 border-b border-border flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-accent" />
              <h1 className="text-lg font-bold tracking-tight text-accent">ZIRAN</h1>
            </div>
            <p className="text-xs text-fg-secondary mt-1">AI Agent Security</p>
          </div>
          <button onClick={() => setMobileOpen(false)} className="md:hidden p-1">
            <X className="h-4 w-4 text-fg-secondary" />
          </button>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-1">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "bg-accent/10 text-accent"
                    : "text-fg-secondary hover:text-fg-primary hover:bg-bg-tertiary"
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-2 py-3 border-t border-border">
          <ThemeToggle />
        </div>
      </aside>
    </>
  )
}
