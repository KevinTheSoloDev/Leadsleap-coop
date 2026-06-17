const ALLOWED_COUNTRIES = ["US", "GB", "CA", "AU", "NZ"]; // LeadsLeap-aligned Tier 1: US, UK, Canada, Australia, New Zealand

const BLOCKED_ASNS = new Set([
  16509, 14618, // Amazon
  15169, 396982, // Google
  8075, // Microsoft
  14061, // DigitalOcean
  16276, // OVH
  24940, // Hetzner
  20473, // Vultr
  63949, // Linode/Akamai
  53667, // FranTech/BuyVM
  9009, // M247
  51167, // Contabo
  45102, // Alibaba
  31898, // Oracle Cloud
  212238, 60068, // Datacamp
  43350, // NForce
  49981, // WorldStream
  60781, 59253, 16265 // LeaseWeb
]);

const BAD_UA_PATTERNS = [
  /bot/i, /crawler/i, /spider/i, /scraper/i,
  /curl/i, /wget/i, /python/i, /requests/i,
  /httpclient/i, /go-http-client/i, /java/i, /node/i, /axios/i,
  /phantom/i, /headless/i, /selenium/i, /playwright/i, /puppeteer/i,
  /scrapy/i, /validator/i
];

function noStoreHeaders(extra = {}) {
  return {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    ...extra
  };
}

function redirectTo(url, result, reason = "") {
  return new Response(null, {
    status: 302,
    headers: noStoreHeaders({
      "Location": url,
      "X-Filter-Result": result,
      "X-Filter-Reason": reason.slice(0, 80)
    })
  });
}

async function checkProxycheck(ip, apiKey) {
  if (!apiKey || !ip) return { ok: true, skipped: true };

  const url = new URL(`https://proxycheck.io/v2/${encodeURIComponent(ip)}`);
  url.searchParams.set("key", apiKey);
  url.searchParams.set("vpn", "1");
  url.searchParams.set("asn", "1");
  url.searchParams.set("risk", "1");
  url.searchParams.set("port", "1");
  url.searchParams.set("seen", "1");
  url.searchParams.set("days", "7");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 900); // keep ZerAds delay low

  try {
    const res = await fetch(url.toString(), { signal: controller.signal });
    const data = await res.json();
    const result = data?.[ip];
    if (!result) return { ok: true, noResult: true };

    const risk = Number(result.risk || 0);
    const proxy = String(result.proxy || "").toLowerCase();
    const type = String(result.type || "").toLowerCase();

    if (proxy === "yes") return { ok: false, reason: `proxycheck_proxy_${type || "unknown"}` };
    if (["vpn", "tor", "proxy", "hosting"].includes(type)) return { ok: false, reason: `proxycheck_type_${type}` };
    if (risk >= 66) return { ok: false, reason: `proxycheck_risk_${risk}` };

    return { ok: true, risk, type };
  } catch (e) {
    // Fail open so API slowness does not waste traffic time.
    return { ok: true, apiError: true };
  } finally {
    clearTimeout(timeout);
  }
}

async function handle(request, env) {
  const cleanUrl = env.LEADSLEAP_URL || "https://lltrco.com/?r=sologotemm";
  const suspiciousUrl = env.SUSPICIOUS_URL || "https://liquidsatoshis.duckdns.org/";
  const cf = request.cf || {};

  if (request.method !== "GET" && request.method !== "HEAD") {
    return redirectTo(suspiciousUrl, "suspicious", "bad_method");
  }

  const ip = request.headers.get("CF-Connecting-IP") || "";
  const ua = request.headers.get("User-Agent") || "";
  const accept = request.headers.get("Accept") || "";
  const acceptLanguage = request.headers.get("Accept-Language") || "";
  const secFetchMode = request.headers.get("Sec-Fetch-Mode") || "";
  const country = cf.country || "XX";
  const asn = Number(cf.asn || 0);
  const tlsVersion = cf.tlsVersion || "";
  const botScore = cf.botManagement?.score;
  const verifiedBot = cf.botManagement?.verifiedBot;

  if (!ua || ua.length < 12 || ua.length > 650) {
    return redirectTo(suspiciousUrl, "suspicious", "bad_user_agent_length");
  }

  for (const pattern of BAD_UA_PATTERNS) {
    if (pattern.test(ua)) return redirectTo(suspiciousUrl, "suspicious", "bad_user_agent");
  }

  if (accept && !accept.includes("text/html") && !accept.includes("*/*")) {
    return redirectTo(suspiciousUrl, "suspicious", "bad_accept_header");
  }

  if (!acceptLanguage && !secFetchMode) {
    return redirectTo(suspiciousUrl, "suspicious", "missing_browser_headers");
  }

  if (ALLOWED_COUNTRIES.length > 0 && !ALLOWED_COUNTRIES.includes(country)) {
    return redirectTo(suspiciousUrl, "suspicious", `country_${country}`);
  }

  if (typeof botScore === "number" && botScore < 15 && !verifiedBot) {
    return redirectTo(suspiciousUrl, "suspicious", `cf_bot_score_${botScore}`);
  }

  if (asn && BLOCKED_ASNS.has(asn)) {
    return redirectTo(suspiciousUrl, "suspicious", `blocked_asn_${asn}`);
  }

  if (tlsVersion && ["TLSv1", "TLSv1.1"].includes(tlsVersion)) {
    return redirectTo(suspiciousUrl, "suspicious", `old_tls_${tlsVersion}`);
  }

  const proxycheck = await checkProxycheck(ip, env.PROXYCHECK_KEY);
  if (!proxycheck.ok) {
    return redirectTo(suspiciousUrl, "suspicious", proxycheck.reason || "proxycheck_block");
  }

  return redirectTo(cleanUrl, "clean", "");
}

export default {
  async fetch(request, env) {
    return handle(request, env || {});
  }
};
