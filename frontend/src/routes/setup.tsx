import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ShieldCheck, KeyRound, Download } from "lucide-react";
import { apiFetch } from "@/lib/api";

export const Route = createFileRoute("/setup")({
  component: SetupWizard,
  head: () => ({ meta: [{ title: "SentiHealth — First-run setup" }] }),
});

type Enrol = { otpauth_uri: string; qr_svg: string; backup_codes: string[]; totp_secret: string };

/**
 * First-run wizard. Replaces "read the TOTP secret off the server console": the admin sets a
 * password, scans a QR code and downloads the backup codes. The backend refuses this route as soon
 * as the default password is gone, so it cannot be used to take over an installed system.
 */
function SetupWizard() {
  const router = useRouter();
  const [status, setStatus] = useState<"checking" | "needed" | "done" | "unreachable">("checking");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [enrol, setEnrol] = useState<Enrol | null>(null);

  useEffect(() => {
    apiFetch("/api/setup/status")
      .then((r) => r.json())
      .then((d: { needs_setup: boolean }) => setStatus(d.needs_setup ? "needed" : "done"))
      .catch(() => setStatus("unreachable"));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password.length < 12) return setError("Use at least 12 characters.");
    if (password !== confirm) return setError("The two passwords differ.");
    setBusy(true);
    try {
      const r = await apiFetch("/api/setup/complete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const d = await r.json();
      if (!r.ok || !d.success) return setError(d.message || "Setup failed.");
      setEnrol(d);
    } catch {
      setError("Cannot reach the security server.");
    } finally {
      setBusy(false);
    }
  };

  const downloadCodes = () => {
    if (!enrol) return;
    const blob = new Blob([`SentiHealth admin backup codes (each works once)\n\n${enrol.backup_codes.join("\n")}\n`], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sentihealth-backup-codes.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-10">
      <section className="w-full max-w-[640px] rounded-3xl border border-border bg-card/95 p-8 shadow-card sm:p-10">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-xl bg-brand-soft text-brand">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">SentiHealth first-run setup</h1>
            <p className="text-[12.5px] text-muted-foreground">One time only. Takes about a minute.</p>
          </div>
        </div>

        {status === "checking" && <p className="text-sm text-muted-foreground">Checking the server…</p>}
        {status === "unreachable" && <p className="text-sm text-warn">The security server is not reachable. Start it with <code>python3 api/dashboard.py</code> and reload.</p>}
        {status === "done" && (
          <div className="space-y-4">
            <p className="text-sm">Setup is already complete on this installation.</p>
            <button onClick={() => router.navigate({ to: "/" })} className="rounded-xl bg-gradient-sentinel px-4 py-2 text-sm font-semibold text-white">Go to login</button>
          </div>
        )}

        {status === "needed" && !enrol && (
          <form onSubmit={submit} className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Step 1 of 3: choose the administrator password. The default one stops working immediately.
            </p>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="New admin password (12+ characters)" className="h-12 w-full rounded-xl border border-input bg-card px-4 text-sm" autoFocus />
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Repeat the password" className="h-12 w-full rounded-xl border border-input bg-card px-4 text-sm" />
            {error && <p className="text-[12.5px] text-alert">{error}</p>}
            <button type="submit" disabled={busy} className="h-12 w-full rounded-xl bg-gradient-sentinel text-[13px] font-semibold uppercase tracking-[0.2em] text-white disabled:opacity-60">
              {busy ? "Saving…" : "Continue"}
            </button>
          </form>
        )}

        {enrol && (
          <div className="space-y-6">
            <div>
              <h2 className="flex items-center gap-2 text-sm font-semibold"><KeyRound className="h-4 w-4" /> Step 2 of 3: scan this QR code in your authenticator app</h2>
              <p className="mt-1 text-[12.5px] text-muted-foreground">Google Authenticator, Authy, Aegis or any TOTP app. Nothing leaves this network: the code is computed on your phone.</p>
              <div className="mt-3 inline-block rounded-2xl bg-white p-3" dangerouslySetInnerHTML={{ __html: enrol.qr_svg }} />
              <details className="mt-2 text-[12px] text-muted-foreground">
                <summary className="cursor-pointer">Can't scan? Enter the key manually</summary>
                <code className="mt-1 block break-all rounded-lg bg-muted/40 p-2 font-mono-sec">{enrol.totp_secret}</code>
              </details>
            </div>
            <div>
              <h2 className="text-sm font-semibold">Step 3 of 3: save your backup codes</h2>
              <p className="mt-1 text-[12.5px] text-muted-foreground">Each code works once if the phone is lost. They are shown only now.</p>
              <div className="mt-2 grid grid-cols-2 gap-1 rounded-xl border border-border bg-muted/30 p-3 font-mono-sec text-[13px] sm:grid-cols-4">
                {enrol.backup_codes.map((c) => <span key={c}>{c}</span>)}
              </div>
              <button type="button" onClick={downloadCodes} className="mt-3 inline-flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-xs font-medium hover:bg-muted">
                <Download className="h-3.5 w-3.5" /> Download codes
              </button>
            </div>
            <button onClick={() => router.navigate({ to: "/" })} className="h-12 w-full rounded-xl bg-gradient-sentinel text-[13px] font-semibold uppercase tracking-[0.2em] text-white">
              Done — go to login
            </button>
          </div>
        )}
      </section>
    </main>
  );
}
