// Vercel serverless function: GET /api/resolve?url=<link safelinku>
const UA =
  "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Jar {
  constructor() { this.c = {}; }
  add(res) {
    const list = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const s of list) {
      const [kv] = s.split(";");
      const i = kv.indexOf("=");
      if (i > 0) this.c[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
    }
  }
  header() { return Object.entries(this.c).map(([k, v]) => `${k}=${v}`).join("; "); }
}

async function get(url, jar, referer) {
  let cur = url;
  for (let i = 0; i < 8; i++) {
    const res = await fetch(cur, {
      redirect: "manual",
      headers: { "user-agent": UA, cookie: jar.header(), ...(referer ? { referer } : {}), accept: "text/html,*/*" },
    });
    jar.add(res);
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      cur = new URL(loc, cur).href;
      // keluar dari domain safelinku = hasil akhir
      if (!/safelinku/i.test(new URL(cur).hostname)) return { final: cur };
      continue;
    }
    return { html: await res.text(), url: cur };
  }
  throw new Error("Terlalu banyak redirect");
}

function hiddenInputs(html) {
  const forms = [...html.matchAll(/<form[^>]*>([\s\S]*?)<\/form>/gi)];
  for (const f of forms) {
    const body = f[1];
    if (!/ad_form_data|_csrfToken|_Token/i.test(body)) continue;
    const data = {};
    for (const m of body.matchAll(/<input[^>]*>/gi)) {
      const tag = m[0];
      const name = (tag.match(/name=["']([^"']+)["']/i) || [])[1];
      const value = (tag.match(/value=["']([^"']*)["']/i) || [])[1] || "";
      if (name) data[name] = value;
    }
    const action = (f[0].match(/action=["']([^"']+)["']/i) || [])[1];
    return { data, action };
  }
  return null;
}

function findTimer(html) {
  const m =
    html.match(/data-timer=["'](\d+)/i) ||
    html.match(/(?:timer|counter|countdown|seconds)\s*[:=]\s*(\d{1,2})\b/i);
  return m ? Math.min(parseInt(m[1], 10), 20) : 6;
}

function sniffUrl(html) {
  const pats = [
    /"url"\s*:\s*"(https?:\\?\/\\?\/[^"]+)"/i,
    /data-(?:url|href|target)=["'](https?:\/\/[^"']+)["']/i,
    /(?:window\.)?location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']+)["']/i,
    /<meta[^>]+http-equiv=["']refresh["'][^>]+url=([^"'>\s]+)/i,
  ];
  for (const p of pats) {
    const m = html.match(p);
    if (m) {
      const u = m[1].replace(/\\\//g, "/");
      if (!/safelinku/i.test(u)) return u;
    }
  }
  for (const m of html.matchAll(/atob\(["']([A-Za-z0-9+/=]{12,})["']\)/g)) {
    try {
      const d = Buffer.from(m[1], "base64").toString();
      if (/^https?:\/\//.test(d) && !/safelinku/i.test(d)) return d;
    } catch {}
  }
  return null;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  const raw = (req.query.url || "").toString().trim();
  let target;
  try {
    target = new URL(raw);
    if (!/^https?:$/.test(target.protocol)) throw 0;
    if (!/(^|\.)safelinku\.[a-z.]+$/i.test(target.hostname)) {
      return res.status(400).json({ ok: false, error: "Hanya link safelinku yang didukung." });
    }
  } catch {
    return res.status(400).json({ ok: false, error: "URL tidak valid." });
  }

  try {
    const jar = new Jar();
    const first = await get(target.href, jar);
    if (first.final) return res.json({ ok: true, url: first.final });

    let html = first.html;
    let pageUrl = first.url;

    // Maksimal 4 tahap (beberapa link punya multi-step)
    for (let step = 0; step < 4; step++) {
      const direct = sniffUrl(html);
      const form = hiddenInputs(html);

      if (!form) {
        if (direct) return res.json({ ok: true, url: direct });
        break;
      }

      await sleep(findTimer(html) * 1000 + 400);

      const origin = new URL(pageUrl).origin;
      const endpoint = new URL(form.action && form.action !== "#" ? form.action : "/links/go", origin).href;
      const post = await fetch(endpoint, {
        method: "POST",
        redirect: "manual",
        headers: {
          "user-agent": UA,
          "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
          "x-requested-with": "XMLHttpRequest",
          accept: "application/json, text/javascript, */*; q=0.01",
          origin,
          referer: pageUrl,
          cookie: jar.header(),
        },
        body: new URLSearchParams(form.data).toString(),
      });
      jar.add(post);

      const loc = post.headers.get("location");
      if (loc && !/safelinku/i.test(new URL(loc, endpoint).hostname)) {
        return res.json({ ok: true, url: new URL(loc, endpoint).href });
      }

      const text = await post.text();
      let json = null;
      try { json = JSON.parse(text); } catch {}

      if (json && json.url && !/safelinku/i.test(json.url)) {
        return res.json({ ok: true, url: json.url });
      }
      if (json && json.url) {
        const next = await get(new URL(json.url, origin).href, jar, pageUrl);
        if (next.final) return res.json({ ok: true, url: next.final });
        html = next.html; pageUrl = next.url;
        continue;
      }
      if (json && json.status === "error") {
        return res.status(422).json({ ok: false, error: json.message || "Ditolak server safelinku (kemungkinan captcha/token)." });
      }
      const sniff = sniffUrl(text);
      if (sniff) return res.json({ ok: true, url: sniff });
      html = text;
    }

    return res.status(422).json({
      ok: false,
      error: "Alur link ini belum dikenali (kemungkinan pakai captcha atau token khusus).",
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Gagal memproses: " + (e.message || "unknown") });
  }
}
