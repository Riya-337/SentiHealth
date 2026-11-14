/**
 * Where the Flask backend (api/dashboard.py) lives, and the explicit demo mode.
 *
 * - Local development: leave VITE_API_BASE_URL unset. Calls go to /api/... and the Vite dev server
 *   proxies them to Flask on localhost:5001 (see vite.config.ts).
 * - Deployed frontend (Vercel): set VITE_API_BASE_URL to the backend's public URL, for example the
 *   ngrok address printed by `python3 api/dashboard.py`, then redeploy (Vite bakes it in at build time).
 *
 * Demo mode is only entered when the user presses "Open demo". It shows simulated data with a visible
 * banner and never pretends to be logged in to the real backend.
 */

const BASE = String(import.meta.env.VITE_API_BASE_URL ?? "")
  .trim()
  .replace(/\/+$/, "");

export function apiUrl(path: string): string {
  return `${BASE}${path}`;
}

export function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  // Free ngrok tunnels answer browser requests with a warning page unless this header is sent.
  if (BASE) headers.set("ngrok-skip-browser-warning", "1");
  return fetch(apiUrl(path), { ...init, headers });
}

/** True when the backend answered with JSON (not an HTML 404/error page from a host with no backend). */
export function isJsonResponse(res: Response): boolean {
  return (res.headers.get("content-type") ?? "").includes("application/json");
}

const DEMO_KEY = "sentihealth.demo";

export function isDemoMode(): boolean {
  return typeof window !== "undefined" && sessionStorage.getItem(DEMO_KEY) === "1";
}

export function enterDemoMode(): void {
  sessionStorage.removeItem("auth_token");
  sessionStorage.setItem("is_admin", "1");
  sessionStorage.setItem(DEMO_KEY, "1");
}

export function exitDemoMode(): void {
  sessionStorage.removeItem(DEMO_KEY);
}
