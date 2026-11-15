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

export function authToken(): string {
  return typeof window !== "undefined" ? (sessionStorage.getItem("auth_token") ?? "") : "";
}

export function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  // Free ngrok tunnels answer browser requests with a warning page unless this header is sent.
  if (BASE) headers.set("ngrok-skip-browser-warning", "1");
  return fetch(apiUrl(path), { ...init, headers });
}

/** Authenticated JSON request helper. */
export async function apiJson<T = Record<string, unknown>>(
  path: string,
  body?: unknown,
  method: "POST" | "DELETE" | "GET" = body === undefined ? "GET" : "POST",
): Promise<{ ok: boolean; status: number; data: T & { success?: boolean; message?: string } }> {
  const res = await apiFetch(path, {
    method,
    headers: { Authorization: `Bearer ${authToken()}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: unknown = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  return { ok: res.ok, status: res.status, data: data as T & { success?: boolean; message?: string } };
}

/** True when the backend answered with JSON (not an HTML 404/error page from a host with no backend). */
export function isJsonResponse(res: Response): boolean {
  return (res.headers.get("content-type") ?? "").includes("application/json");
}

/**
 * Server-sent events without the session token in the URL. EventSource cannot set headers, so the
 * page first asks the backend for a one-time 60-second ticket (POST /api/stream/ticket) and opens the
 * stream with that. Listeners registered before the ticket arrives are attached when it does.
 */
export class LazyStream {
  private es: EventSource | null = null;
  private closed = false;
  private pending: Array<[string, (e: MessageEvent) => void]> = [];
  private _onerror: (() => void) | null = null;

  constructor() {
    const token = authToken();
    if (!token) return;
    apiFetch("/api/stream/ticket", { method: "POST", headers: { Authorization: `Bearer ${token}` } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then((d: { ticket: string }) => {
        if (this.closed) return;
        this.es = new EventSource(apiUrl(`/api/stream?ticket=${encodeURIComponent(d.ticket)}`));
        for (const [type, cb] of this.pending) this.es.addEventListener(type, cb as EventListener);
        this.pending = [];
        this.es.onerror = () => this._onerror?.();
      })
      .catch(() => this._onerror?.());
  }

  addEventListener(type: string, cb: (e: MessageEvent) => void): void {
    if (this.es) this.es.addEventListener(type, cb as EventListener);
    else this.pending.push([type, cb]);
  }

  set onerror(cb: (() => void) | null) {
    this._onerror = cb;
    if (this.es) this.es.onerror = () => cb?.();
  }

  close(): void {
    this.closed = true;
    this.es?.close();
    this.es = null;
  }
}

export function openStream(): LazyStream {
  return new LazyStream();
}

/** Step-up MFA for destructive actions: the backend requires a fresh authenticator code. */
export function askTotp(action: string): string | null {
  const code =
    typeof window !== "undefined"
      ? window.prompt(`${action}\n\nEnter your 6-digit authenticator code (or a backup code):`)
      : null;
  const trimmed = (code ?? "").trim();
  return trimmed.length >= 6 ? trimmed : null;
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
