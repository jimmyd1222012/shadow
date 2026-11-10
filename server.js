const express = require("express");
const dns = require("node:dns").promises;
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const cheerio = require("cheerio");
const path = require("node:path");

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 4;

// Add domains you own or are authorized to access, comma-separated.
// Example: ALLOWED_HOSTS=example.com,docs.example.org
const ALLOWED_HOSTS = new Set(
  (process.env.ALLOWED_HOSTS || "")
    .split(",")
    .map(x => x.trim().toLowerCase())
    .filter(Boolean)
);

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});
app.use(express.static(path.join(__dirname, "public")));

function isPublicIp(address) {
  if (!net.isIP(address)) return false;
  const parsed = ipaddr.parse(address);
  return parsed.range() === "unicast";
}

async function validateUrl(raw) {
  let url;
  try { url = new URL(raw); } catch { throw new Error("Enter a valid URL."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS URLs are supported.");
  if (url.username || url.password) throw new Error("URLs containing usernames or passwords are not allowed.");
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error(`This domain is not on the allowlist. Add ${host} to ALLOWED_HOSTS in Replit Secrets if you are authorized to access it.`);
  }
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new Error("Local network destinations are blocked.");
  }

  const records = await dns.lookup(host, { all: true, verbatim: true }).catch(() => []);
  if (!records.length || records.some(record => !isPublicIp(record.address))) {
    throw new Error("The destination could not be verified as a public internet host.");
  }
  return url;
}

async function fetchSafely(startUrl) {
  let current = startUrl;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    current = await validateUrl(current.href);
    const response = await fetch(current, {
      redirect: "manual",
      signal: AbortSignal.timeout(12000),
      headers: { "User-Agent": "AuthorizedWebReader/1.0" }
    });

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new Error("The destination returned an invalid redirect.");
      if (hop === MAX_REDIRECTS) throw new Error("Too many redirects.");
      current = new URL(location, current);
      continue;
    }

    const type = (response.headers.get("content-type") || "").toLowerCase();
    if (!(type.includes("text/html") || type.includes("text/plain"))) {
      throw new Error("For safety, this reader only displays HTML and plain-text pages.");
    }

    const declaredLength = Number(response.headers.get("content-length") || 0);
    if (declaredLength > MAX_BYTES) throw new Error("The page is larger than the 2 MB limit.");

    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BYTES) {
        await reader.cancel();
        throw new Error("The page is larger than the 2 MB limit.");
      }
      chunks.push(Buffer.from(value));
    }
    return { status: response.status, type, body: Buffer.concat(chunks).toString("utf8"), finalUrl: current.href };
  }
  throw new Error("Unable to load this page.");
}

app.get("/api/read", async (req, res) => {
  try {
    if (!req.query.url) return res.status(400).json({ error: "Add a URL to read." });
    const result = await fetchSafely(String(req.query.url));
    let title = result.finalUrl;
    let content = "";

    if (result.type.includes("text/html")) {
      const $ = cheerio.load(result.body);
      title = $("title").first().text().trim() || title;
      $("script, style, noscript, iframe, object, embed, form, input, button, video, audio, svg, canvas").remove();
      $("*").each((_, el) => {
        const node = $(el);
        for (const attr of Object.keys(el.attribs || {})) {
          if (/^on/i.test(attr) || attr.toLowerCase() === "srcdoc") node.removeAttr(attr);
        }
      });
      content = $("body").text().replace(/\s+/g, " ").trim();
    } else {
      content = result.body.replace(/\s+/g, " ").trim();
    }

    res.json({ title, url: result.finalUrl, content: content.slice(0, 50000) });
  } catch (error) {
    res.status(400).json({ error: error.message || "Unable to load that page." });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Authorized web reader listening on ${PORT}`);
  if (!ALLOWED_HOSTS.size) console.warn("Set ALLOWED_HOSTS in Replit Secrets before using the reader.");
});