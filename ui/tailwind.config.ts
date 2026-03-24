import type { Config } from "tailwindcss"

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        accent: {
          DEFAULT: "#4fd1c5",
          hover: "#38b2ac",
          light: "#81e6d9",
        },
        "bg-primary": "#0a0a0a",
        "bg-secondary": "#111111",
        "bg-tertiary": "#1a1a1a",
        border: "#27272a",
        severity: {
          danger: "#f87171",
          "warning-orange": "#fb923c",
          "warning-yellow": "#fbbf24",
          safe: "#4ade80",
          muted: "#71717a",
        },
        "fg-primary": "#fafafa",
        "fg-secondary": "#a1a1aa",
      },
      fontFamily: {
        sans: ["DM Sans", "system-ui", "-apple-system", "sans-serif"],
      },
    },
  },
  plugins: [],
} satisfies Config
