import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: "var(--bg-canvas)",
        panel: "var(--bg-panel)",
        elevated: "var(--bg-elevated)",
        subtle: "var(--bg-subtle)",
        ink: "var(--text-ink)",
        "ink-secondary": "var(--text-secondary)",
        "ink-muted": "var(--text-muted)",
        hairline: "var(--border-hairline)",
        "hairline-strong": "var(--border-strong)",
        signal: {
          emerald: "var(--signal-emerald)",
          "emerald-bg": "var(--signal-emerald-bg)",
          "emerald-border": "var(--signal-emerald-border)",
          champagne: "var(--signal-champagne)",
          "champagne-bg": "var(--signal-champagne-bg)",
          "champagne-border": "var(--signal-champagne-border)",
          ochre: "var(--signal-ochre)",
          "ochre-bg": "var(--signal-ochre-bg)",
          "ochre-border": "var(--signal-ochre-border)",
          vermilion: "var(--signal-vermilion)",
          "vermilion-bg": "var(--signal-vermilion-bg)",
          "vermilion-border": "var(--signal-vermilion-border)",
        },
      },
      fontFamily: {
        display: [
          "var(--font-display)",
          "Iowan Old Style",
          "Georgia",
          "Times New Roman",
          "serif",
        ],
        sans: [
          "var(--font-sans)",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "sans-serif",
        ],
        mono: [
          "var(--font-mono)",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      letterSpacing: {
        tightest: "-0.028em",
        telemetry: "-0.02em",
      },
    },
  },
  plugins: [],
};

export default config;
