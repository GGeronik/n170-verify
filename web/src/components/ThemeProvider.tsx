"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type StudioTheme = "obsidian" | "paper";

interface ThemeContextValue {
  theme: StudioTheme;
  setTheme: (next: StudioTheme) => void;
  toggleTheme: () => void;
}

const STORAGE_KEY = "n170-verify-theme";

const ThemeContext = createContext<ThemeContextValue>({
  theme: "obsidian",
  setTheme: () => undefined,
  toggleTheme: () => undefined,
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<StudioTheme>("obsidian");

  useEffect(() => {
    try {
      const params = new URLSearchParams(window.location.search);
      const queryTheme = params.get("theme");
      if (queryTheme === "paper" || queryTheme === "obsidian") {
        setThemeState(queryTheme);
        document.documentElement.setAttribute("data-theme", queryTheme);
        return;
      }
      const attrTheme = document.documentElement.getAttribute("data-theme");
      if (attrTheme === "paper" || attrTheme === "obsidian") {
        setThemeState(attrTheme);
        return;
      }
      const saved = window.localStorage.getItem(STORAGE_KEY);
      if (saved === "paper" || saved === "obsidian") {
        setThemeState(saved);
        document.documentElement.setAttribute("data-theme", saved);
      }
    } catch {
      // Ignore storage access errors in strict sandboxed iframes
    }
  }, []);

  const setTheme = useCallback((next: StudioTheme) => {
    setThemeState(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Ignore storage write errors
    }
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => {
      const next: StudioTheme = prev === "obsidian" ? "paper" : "obsidian";
      document.documentElement.setAttribute("data-theme", next);
      try {
        window.localStorage.setItem(STORAGE_KEY, next);
      } catch {
        // Ignore
      }
      return next;
    });
  }, []);

  const value = useMemo(
    () => ({ theme, setTheme, toggleTheme }),
    [theme, setTheme, toggleTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}
