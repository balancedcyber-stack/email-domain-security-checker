// Cloudflare Worker — Email Domain Security Checker
// Same-origin default: mount on
//   <YOUR_DOMAIN>/scan*
//   www.<YOUR_DOMAIN>/scan*
// Frontend should call:  const API = "/scan";

const DEFAULT_SELECTORS = ["selector1", "selector2"];
const DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query";

// Optional CORS (uncomment if using cross-origin)
// const ALLOW_ORIGINS = ["https://<YOUR_SITE_ORIGIN>", "https://www.<YOUR_SITE_ORIGIN>"];
// function corsHeaders(req) {
//   const origin = req.headers.get("Origin") || "";
//   const allow = ALLOW_ORIGINS.includes(origin) ? origin : ALLOW_ORIGINS[0];
//   return {
//     "Access-Control-Allow-Origin": allow,
//     "Access-Control-Allow-Methods": "GET, OPTIONS",
//     "Access-Control-Allow-Headers": "Content-Type"
//   };
// }

// Burst limiter (best-effort, per instance)
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const bucket = `${ip}:${Math.floor(now / 60000)}`;
  const count = (hits.get(bucket) || 0) + 1;
  hits.set(bucket, count);
  return count > 30;
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store, max-age=0",
    },
  });
}

function isValidDomain(d) {
  return /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(d);
}

async function doh(name, type = "TXT") {
  const url = `${DNS_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
  const r = await fetch(url, { headers: { accept: "application/dns-json" } });
  if (!r.ok) return null;
  return r.json();
}

function extractTXT(json) {
  if (!json || !json.Answer) return [];
  return json.Answer
    .filter(a => a.type === 16)
    .map(a => a.data.replace(/^"|"$/g, "").replace(/\"\s+\"/g, ""));
}

function firstCNAME(json) {
  if (!json || !json.Answer) return "";
  const a = json.Answer.find(x => x.type === 5);
  return a ? a.data : "";
}

// ===== Assessors =====
function assessSPF(domain, txts) {
  const spfs = txts.filter(s => /^v=spf1/i.test(s));
  if (spfs.length === 0) {
    return { control: "SPF", status: "FAIL", detail: "", fix: "Publish a single SPF TXT: v=spf1 <includes/mechanisms> ~all" };
  }
  const issues = [];
  if (spfs.length > 1) issues.push("Multiple SPF records (merge to one).");
  const spf = spfs[0];
  if (!/(~all|-all|\?all)\b/i.test(spf)) issues.push("Missing terminal qualifier (~all or -all).");
  if (spf.length > 255) issues.push("SPF string exceeds 255 characters.");
  return { control: "SPF", status: issues.length ? "WARN" : "PASS", detail: spf, fix: issues.join("; ") };
}

function parseDMARC(rec) {
  const tags = {};
  rec.split(";").map(s => s.trim()).filter(Boolean).forEach(kv => {
    const i = kv.indexOf("=");
    if (i > 0) tags[kv.slice(0,i).toLowerCase()] = kv.slice(i+1).trim();
  });
  return tags;
}

function assessDMARC(txts) {
  const dmarcs = txts.filter(s => /^v=DMARC1/i.test(s));
  if (dmarcs.length === 0) {
    return { control: "DMARC", status: "FAIL", detail: "", fix: "Publish _dmarc TXT: v=DMARC1; p=none; rua=mailto:reports@<YOUR_DOMAIN>" };
  }
  const rec = dmarcs[0];
  const tags = parseDMARC(rec);
  const issues = [];
  if (!("p" in tags)) issues.push('Missing policy tag "p" (none/quarantine/reject).');
  else if (!/^(none|quarantine|reject)$/i.test(tags.p)) issues.push('Invalid "p" value.');
  if (!("rua" in tags)) issues.push('Missing "rua" for aggregate reports.');
  return { control: "DMARC", status: issues.length ? "WARN" : "PASS", detail: rec, fix: issues.join("; ") };
}

function assessDKIM(selector, txts, cnameTarget) {
  let present = false, valid = false, mode = "None", detail = "", issues = [];
  if (txts.length) {
    present = true; mode = "TXT"; detail = txts.join(" ");
    if (/v=DKIM1/i.test(detail) && /p=/i.test(detail)) valid = true;
    else issues.push("DKIM TXT found but no public key (p=) detected.");
  } else if (cnameTarget) {
    present = true; mode = "CNAME"; detail = cnameTarget; valid = true;
  }
  const status = !present ? "FAIL" : (valid ? "PASS" : "WARN");
  const fix = !present ? `Publish DKIM for ${selector} (TXT p=key or CNAME to provider).` : (valid ? "" : issues.join("; "));
  return { control: `DKIM (${selector})`, status, detail, fix };
}

// ===== Entry =====
export default {
  async fetch(req) {
    // For same-origin, no CORS headers needed.
    if (req.method === "OPTIONS") return new Response(null);

    const url = new URL(req.url);
    if (!url.pathname.startsWith("/scan")) return json({ error: "Not found" }, 404);

    const ip = req.headers.get("CF-Connecting-IP") || "0.0.0.0";
    if (limited(ip)) return json({ error: "Rate limit exceeded. Try again shortly." }, 429);

    const domain = (url.searchParams.get("domain") || "").trim().toLowerCase();
    const selectorsParam = (url.searchParams.get("selectors") || "").trim();
    const selectors = selectorsParam ? selectorsParam.split(",").map(s => s.trim()).filter(Boolean) : DEFAULT_SELECTORS;
    if (!isValidDomain(domain)) return json({ error: "Invalid domain." }, 400);

    const spf = assessSPF(domain, extractTXT(await doh(domain, "TXT")));
    const dmarc = assessDMARC(extractTXT(await doh(`_dmarc.${domain}`, "TXT")));

    const dkim = [];
    for (const s of selectors) {
      const host = `${s}._domainkey.${domain}`;
      dkim.push(assessDKIM(s, extractTXT(await doh(host, "TXT")), firstCNAME(await doh(host, "CNAME"))));
    }

    const statuses = [spf.status, dmarc.status, ...dkim.map(x => x.status)];
    const overall = statuses.includes("FAIL") ? "FAIL" : (statuses.includes("WARN") ? "WARN" : "PASS");
    return json({ domain, selectors, overall, items: [spf, dmarc, ...dkim], ts: new Date().toISOString() });
  }
};
