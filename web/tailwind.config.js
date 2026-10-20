/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          900: "#0a0e14",
          800: "#0f141c",
          700: "#161c26",
          600: "#1e2630",
        },
        line: "#232c38",
        accent: {
          DEFAULT: "#22d3ee",
          dim: "#0e7490",
        },
        ok: "#34d399",
        warn: "#fbbf24",
        bad: "#f87171",
        muted: "#7d8aa0",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        card: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
      },
    },
  },
  plugins: [],
};
