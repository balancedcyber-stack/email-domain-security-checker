# Email Domain Security Checker (SPF / DKIM / DMARC)

A simple, production-ready way to add an **email domain security check** to your website.
It has three parts:

- **Cloudflare Worker API** (`/scan`) that looks up SPF, DMARC and DKIM records over DNS‑over‑HTTPS and returns JSON.
- **Frontend Widget** you can paste into any site (WordPress, static HTML, etc.).
- **Optional PowerShell Script** for CLI use and HTML/CSV reporting.

> This repository is unbranded on purpose. Replace placeholders like `<YOUR_DOMAIN>` with your values.

---

## Features

- PASS / WARN / FAIL for SPF, DMARC and DKIM (with clear, plain-English fixes).
- Long TXT values are neatly wrapped; safe for mobile.
- Same-origin default (no CORS headaches). Optional cross-origin snippet included.
- Lightweight burst limiter in the Worker.
- Optional PowerShell script produces HTML and CSV evidence for auditors/insurers.

---

## Quick Start (Same-Origin, Recommended)

1. **Create a Worker** (Cloudflare → Workers & Pages → Workers → Create → Quick edit).
2. Paste the code from `worker/worker.js` and save.
3. **Bind routes** under the Worker → Triggers → Routes:

   ```
   <YOUR_DOMAIN>/scan*
   www.<YOUR_DOMAIN>/scan*
   ```

   Make sure your DNS for `<YOUR_DOMAIN>` and `www` are **proxied (orange cloud)**.

4. **Add the widget** to your site:
   - Open `web/widget.html`, leave `const API = "/scan"` (same-origin), and paste its contents into your page.  
     WordPress: add a “Custom HTML” block and paste everything from `web/widget.html`.

5. **Test** in a browser:

   - Visit `https://<YOUR_DOMAIN>/scan?domain=example.com&selectors=selector1,selector2` – you should see JSON.
   - On your page, enter a domain and click **Run check**.

---

## Alternative: Cross-Origin (Custom Subdomain)

If you prefer `https://scan.<YOUR_DOMAIN>/scan`:

1. In the Worker → **Custom Domains**, add `scan.<YOUR_DOMAIN>`.
2. Point the widget’s `API` constant to the full URL:

   ```js
   const API = "https://scan.<YOUR_DOMAIN>/scan";
   ```

3. If you serve the widget from a different origin, enable CORS (see commented snippet inside `worker/worker.js`).

---

## Optional CLI: PowerShell Script

The script in `powershell/EmailAuthCheck.ps1` runs locally, performs the same checks, and can export HTML/CSV.

**Examples:**

```powershell
# Basic scan
.\powershell\EmailAuthCheck.ps1 -Domain example.com

# With HTML + CSV reports
.\powershell\EmailAuthCheck.ps1 -Domain example.com -Html -Csv

# Custom DKIM selectors
.\powershell\EmailAuthCheck.ps1 -Domain example.com -DkimSelectors 'selector1','selector2','smtp'
```

---

## Security Notes

- Read-only: only public DNS is queried via Cloudflare DoH (`https://cloudflare-dns.com/dns-query`).
- No secrets required; no tenant access.
- Worker includes a minimal per-minute rate limiter.
- Add a WAF rule if you want stricter throttling (Cloudflare → Security → WAF).

---

## Troubleshooting

- **HTML instead of JSON** when calling `/scan`: the Worker route isn’t attached or DNS isn’t proxied.
- **CORS error** (only in cross-origin mode): allow your site’s origin in the Worker CORS allowlist.
- **Button overlaps input**: the widget uses Flex + `gap`; some themes cache CSS. Clear caches and refresh.

---

## Folder Structure

```text
email-domain-security-checker/
├─ worker/
│  └─ worker.js             # Cloudflare Worker (same-origin by default)
├─ web/
│  └─ widget.html           # Paste into your site
├─ powershell/
│  └─ EmailAuthCheck.ps1    # Optional CLI + HTML/CSV output
├─ .github/workflows/
│  └─ ci.yml                # Optional: basic lint/format on PRs
├─ LICENSE                  # MIT
└─ README.md
```

---

## License

MIT — see `LICENSE`.
