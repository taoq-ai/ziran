import { Moon, Sun } from "lucide-react"
import { useEffect, useState } from "react"

export function ThemeToggle() {
  const [dark, setDark] = useState(() => {
    if (typeof window === "undefined") return true
    return localStorage.getItem("theme") !== "light"
  })

  useEffect(() => {
    const root = document.documentElement
    if (dark) {
      root.classList.remove("light")
      root.classList.add("dark")
      localStorage.setItem("theme", "dark")
    } else {
      root.classList.remove("dark")
      root.classList.add("light")
      localStorage.setItem("theme", "light")
    }
  }, [dark])

  return (
    <button
      onClick={() => setDark(!dark)}
      className="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-fg-secondary hover:bg-bg-tertiary hover:text-fg-primary transition-colors duration-150"
      aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      <span>{dark ? "Light Mode" : "Dark Mode"}</span>
    </button>
  )
}
