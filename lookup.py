#!/usr/bin/env python3
"""
LOOKUP — open-source intelligence lookup CLI.

Targets: domains, IPs, emails, usernames (cross-platform), Roblox users/IDs.
Uses only free, public, unauthenticated sources.

Usage:
    python lookup.py                     interactive mode
    python lookup.py <query>             auto-detect and run everything relevant
    python lookup.py domain example.com
    python lookup.py ip 8.8.8.8
    python lookup.py email someone@example.com
    python lookup.py user someusername
    python lookup.py roblox Builderman | 156
    add --json out.json to any command to save raw results
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
except ImportError:
    print("Missing dependencies. Run:  pip install -r requirements.txt")
    sys.exit(1)

try:
    import dns.resolver  # type: ignore
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

# ──────────────────────────────────────────────────────────────────────────────
# Style — monochrome, formal
# ──────────────────────────────────────────────────────────────────────────────
THEME = Theme({
    "title": "bold white",
    "label": "grey62",
    "value": "white",
    "dim": "grey42",
    "hit": "bold white",
    "miss": "grey35",
    "warn": "grey70 italic",
    "rule": "grey23",
})
console = Console(theme=THEME, highlight=False)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
session = requests.Session()
session.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
TIMEOUT = 10


def get(url, **kw):
    kw.setdefault("timeout", TIMEOUT)
    return session.get(url, **kw)


def get_json(url, **kw):
    try:
        r = get(url, **kw)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Rendering helpers
# ──────────────────────────────────────────────────────────────────────────────
def banner():
    console.print()
    console.print(Text("L O O K U P", style="title"), justify="center")
    console.print(Text("open-source intelligence  ·  public sources only", style="dim"),
                  justify="center")
    console.print()


def section(title: str):
    console.print()
    console.rule(Text(f" {title.upper()} ", style="title"), style="rule", align="left")


def kv_table(rows: list[tuple[str, object]]):
    t = Table(box=None, show_header=False, padding=(0, 2, 0, 1))
    t.add_column(style="label", no_wrap=True)
    t.add_column(style="value", overflow="fold")
    for k, v in rows:
        if v is None or v == "" or v == []:
            v = Text("—", style="miss")
        elif isinstance(v, (list, tuple)):
            v = "\n".join(str(x) for x in v)
        t.add_row(k, v if isinstance(v, Text) else str(v))
    console.print(t)


def list_table(headers: list[str], rows: list[list[object]]):
    t = Table(box=box.SIMPLE_HEAD, header_style="label", border_style="rule",
              padding=(0, 2, 0, 1))
    for h in headers:
        t.add_column(h, style="value", overflow="fold")
    for r in rows:
        t.add_row(*[str(x) if x is not None else "—" for x in r])
    console.print(t)


def note(msg: str):
    console.print(Text(f"  {msg}", style="warn"))


def fmt_date(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except Exception:
        return s


# ──────────────────────────────────────────────────────────────────────────────
# Domain
# ──────────────────────────────────────────────────────────────────────────────
def dns_records(domain: str) -> dict:
    out = {}
    if not HAVE_DNS:
        try:
            out["A"] = sorted({a[4][0] for a in socket.getaddrinfo(domain, None)})
        except Exception:
            pass
        return out
    res = dns.resolver.Resolver()
    res.lifetime = 6
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"):
        try:
            ans = res.resolve(domain, rtype)
            out[rtype] = [r.to_text().strip('"') for r in ans]
        except Exception:
            continue
    return out


def rdap_domain(domain: str) -> dict:
    data = get_json(f"https://rdap.org/domain/{domain}")
    if not data:
        return {}
    info = {"status": data.get("status", [])}
    for ev in data.get("events", []):
        a = ev.get("eventAction")
        if a in ("registration", "expiration", "last changed"):
            info[a] = fmt_date(ev.get("eventDate"))
    info["nameservers"] = [n.get("ldhName", "").lower() for n in data.get("nameservers", [])]
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn":
                    info["registrar"] = item[3]
    return info


def crtsh_subdomains(domain: str) -> list[str]:
    try:
        r = get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        if not r.ok:
            return []
        names = set()
        for row in r.json():
            for n in row.get("name_value", "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(domain):
                    names.add(n)
        return sorted(names)
    except Exception:
        return []


def http_probe(domain: str) -> dict:
    for scheme in ("https", "http"):
        try:
            r = get(f"{scheme}://{domain}", allow_redirects=True)
            title = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            return {
                "url": r.url,
                "status": r.status_code,
                "server": r.headers.get("Server"),
                "powered by": r.headers.get("X-Powered-By"),
                "title": title.group(1).strip()[:120] if title else None,
            }
        except Exception:
            continue
    return {}


SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
               "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
TECH_SIGNS = {
    "Cloudflare": ["cf-ray", "cloudflare"], "WordPress": ["wp-content", "wp-json"],
    "Shopify": ["cdn.shopify", "x-shopid"], "Wix": ["wix.com", "x-wix"],
    "Squarespace": ["squarespace"], "Next.js": ["__next", "x-nextjs"], "React": ["react"],
    "Vercel": ["x-vercel"], "Netlify": ["netlify"], "GitHub Pages": ["github.io", "x-github-request"],
    "nginx": ["nginx"], "Apache": ["apache"], "Google Analytics": ["googletagmanager", "gtag("],
    "Discord invite": ["discord.gg/", "discord.com/invite"], "Roblox link": ["roblox.com/"],
}


def web_extras(domain: str) -> dict:
    out = {"security_headers": {}, "tech": []}
    try:
        r = get(f"https://{domain}", allow_redirects=True)
        for h in SEC_HEADERS:
            out["security_headers"][h] = "present" if h in r.headers else "missing"
        blob = (str(dict(r.headers)) + r.text[:200000]).lower()
        out["tech"] = [k for k, v in TECH_SIGNS.items() if any(x in blob for x in v)]
        out["links_out"] = sorted(set(re.findall(
            r"https?://(?:www\.)?((?:discord\.gg|t\.me|youtube\.com|x\.com|twitter\.com|"
            r"instagram\.com|tiktok\.com|github\.com|roblox\.com)/[\w@./-]{2,60})", r.text)))[:25]
    except Exception:
        pass
    return out


def wayback(domain: str) -> dict:
    out = {}
    for key, lim in (("first_archived", "1"), ("last_archived", "-1")):
        j = get_json(f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit={lim}"
                     "&fl=timestamp", timeout=15)
        if j and len(j) > 1:
            t = j[1][0]
            out[key] = f"{t[:4]}-{t[4:6]}-{t[6:8]}"
    if out:
        out["archive"] = f"https://web.archive.org/web/*/{domain}"
    return out


def lookup_domain(domain: str) -> dict:
    domain = domain.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
    section(f"domain · {domain}")
    with console.status("[dim]querying registry, DNS, certificates…", spinner="line"):
        with ThreadPoolExecutor(6) as ex:
            f_rdap = ex.submit(rdap_domain, domain)
            f_dns = ex.submit(dns_records, domain)
            f_http = ex.submit(http_probe, domain)
            f_crt = ex.submit(crtsh_subdomains, domain)
            f_x = ex.submit(web_extras, domain)
            f_wb = ex.submit(wayback, domain)
            rdap, recs, web, subs = f_rdap.result(), f_dns.result(), f_http.result(), f_crt.result()
            extras, wb = f_x.result(), f_wb.result()

    console.print(Text("  Registration", style="label"))
    kv_table([
        ("Registrar", rdap.get("registrar")),
        ("Registered", rdap.get("registration")),
        ("Expires", rdap.get("expiration")),
        ("Updated", rdap.get("last changed")),
        ("Status", rdap.get("status")),
    ])
    console.print(Text("\n  DNS", style="label"))
    kv_table([(k, v) for k, v in recs.items()] or [("Records", None)])
    console.print(Text("\n  Web", style="label"))
    kv_table([(k.title(), v) for k, v in web.items()] or [("Reachable", "no")])
    console.print(Text("\n  Technology & security", style="label"))
    kv_table([("Detected", ", ".join(extras.get("tech", [])) or None)] +
             [(k, v) for k, v in extras.get("security_headers", {}).items()] +
             [("Outbound social links", extras.get("links_out"))])
    console.print(Text("\n  History", style="label"))
    kv_table([(k.replace("_", " ").title(), v) for k, v in wb.items()] or [("Wayback", None)])
    console.print(Text(f"\n  Subdomains from certificate logs ({len(subs)})", style="label"))
    if subs:
        shown = subs[:40]
        kv_table([("", "\n".join(shown) + (f"\n… +{len(subs)-40} more" if len(subs) > 40 else ""))])
    else:
        note("none found or crt.sh unavailable")

    ips = recs.get("A", [])
    return {"type": "domain", "query": domain, "rdap": rdap, "dns": recs,
            "web": web, "technology": extras.get("tech"),
            "security_headers": extras.get("security_headers"),
            "outbound_social_links": extras.get("links_out"), "history": wb,
            "subdomains": subs, "_ips": ips}


# ──────────────────────────────────────────────────────────────────────────────
# IP
# ──────────────────────────────────────────────────────────────────────────────
def lookup_ip(ip: str) -> dict:
    section(f"ip · {ip}")
    with console.status("[dim]querying geolocation, ASN, RDAP…", spinner="line"):
        info = get_json(f"https://ipinfo.io/{ip}/json") or {}
        rdap = get_json(f"https://rdap.org/ip/{ip}") or {}
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except Exception:
            rdns = None
        idb = get_json(f"https://internetdb.shodan.io/{ip}") or {}
        bl = dnsbl(ip)
    kv_table([
        ("Reverse DNS", rdns or info.get("hostname")),
        ("Organization / ASN", info.get("org")),
        ("Network", rdap.get("name")),
        ("Range", f"{rdap.get('startAddress')} – {rdap.get('endAddress')}"
            if rdap.get("startAddress") else None),
        ("City", info.get("city")),
        ("Region", info.get("region")),
        ("Country", info.get("country") or rdap.get("country")),
        ("Coordinates", info.get("loc")),
        ("Timezone", info.get("timezone")),
        ("Anycast", "yes" if info.get("anycast") else None),
        ("Open ports (Shodan)", ", ".join(map(str, idb.get("ports", []))) or None),
        ("Services", idb.get("cpes")),
        ("Tags", idb.get("tags")),
        ("Known CVEs", ", ".join(idb.get("vulns", [])[:15]) or None),
        ("Hostnames", idb.get("hostnames")),
        ("Blocklists", ", ".join(k for k, v in bl.items() if v) or
         ("clean" if any(v is False for v in bl.values()) else "couldn't check")),
    ])
    note("IP geolocation is approximate — usually the ISP's location, not a person's.")
    return {"type": "ip", "query": ip, "rdns": rdns, "ipinfo": info,
            "rdap_name": rdap.get("name"), "shodan_internetdb": idb, "blocklists": bl}


DNSBLS = {"Spamhaus ZEN": "zen.spamhaus.org", "SpamCop": "bl.spamcop.net",
          "Barracuda": "b.barracudacentral.org", "SORBS": "dnsbl.sorbs.net"}


def dnsbl(ip: str) -> dict:
    try:
        if ipaddress.ip_address(ip).version != 4:
            return {}
    except ValueError:
        return {}
    rev = ".".join(reversed(ip.split(".")))
    out = {}
    for name, zone in DNSBLS.items():
        try:
            ans = socket.gethostbyname(f"{rev}.{zone}")
            # 127.255.255.x = the list refused the query (common on cloud/public DNS), not a listing
            out[name] = None if ans.startswith("127.255.255.") or not ans.startswith("127.") else True
        except Exception:
            out[name] = False
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Email
# ──────────────────────────────────────────────────────────────────────────────
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "trashmail.com", "getnada.com", "sharklasers.com",
    "dispostable.com", "maildrop.cc", "throwawaymail.com", "fakeinbox.com",
    "mailnesia.com", "mohmal.com", "emailondeck.com", "tempr.email", "discard.email",
}
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com",
    "zoho.com", "yandex.com", "mail.com", "privaterelay.appleid.com",
}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def lookup_email(email: str) -> dict:
    email = email.strip().lower()
    local, _, domain = email.partition("@")
    section(f"email · {email}")
    with console.status("[dim]checking mail servers and public profiles…", spinner="line"):
        recs = dns_records(domain)
        mx = recs.get("MX", [])
        spf = [t for t in recs.get("TXT", []) if t.lower().startswith("v=spf1")]
        dmarc = []
        if HAVE_DNS:
            try:
                dmarc = [r.to_text().strip('"') for r in
                         dns.resolver.resolve(f"_dmarc.{domain}", "TXT")]
            except Exception:
                pass
        h = hashlib.sha256(email.encode()).hexdigest()
        grav = get_json(f"https://en.gravatar.com/{h}.json")
        grav_entry = (grav or {}).get("entry", [{}])[0] if grav else {}

    if domain in DISPOSABLE:
        kind = "disposable"
    elif domain in FREE_PROVIDERS:
        kind = "free provider"
    else:
        kind = "custom / organisational"
    kv_table([
        ("Syntax", "valid" if EMAIL_RE.match(email) else "invalid"),
        ("Local part", local),
        ("Domain", domain),
        ("Domain type", kind),
        ("Accepts mail (MX)", "\n".join(mx) if mx else "no MX records"),
        ("SPF", spf[0] if spf else None),
        ("DMARC", dmarc[0] if dmarc else None),
    ])
    console.print(Text("\n  Gravatar public profile", style="label"))
    if grav_entry:
        kv_table([
            ("Display name", grav_entry.get("displayName")),
            ("Profile", grav_entry.get("profileUrl")),
            ("About", grav_entry.get("aboutMe")),
            ("Linked accounts", [f"{a.get('shortname')}: {a.get('url')}"
                                 for a in grav_entry.get("accounts", [])]),
        ])
    else:
        note("no public Gravatar profile")
    note(f"Tip: run  user {local}  to check the local part as a username.")
    return {"type": "email", "query": email, "domain_type": kind, "mx": mx,
            "spf": spf, "dmarc": dmarc, "gravatar": grav_entry or None}


# ──────────────────────────────────────────────────────────────────────────────
# Username presence (cross-platform)
# ──────────────────────────────────────────────────────────────────────────────
# Each site: name, profile URL, check URL, detection method.
#   "status"  → found if HTTP 200, absent if 404 (or 410)
#   "text:X"  → absent if X appears in body
#   "json"    → custom lambda on parsed JSON returning True/False
SITES = [
    ("GitHub", "https://github.com/{}", "https://github.com/{}", "status"),
    ("GitLab", "https://gitlab.com/{}", "https://gitlab.com/api/v4/users?username={}",
     lambda j: isinstance(j, list) and len(j) > 0),
    ("Codeberg", "https://codeberg.org/{}", "https://codeberg.org/api/v1/users/{}", "status"),
    ("Bitbucket", "https://bitbucket.org/{}/", "https://bitbucket.org/{}/", "status"),
    ("Reddit", "https://reddit.com/user/{}", "https://www.reddit.com/user/{}/about.json",
     lambda j: isinstance(j, dict) and "data" in j),
    ("Steam", "https://steamcommunity.com/id/{}", "https://steamcommunity.com/id/{}",
     "text:The specified profile could not be found"),
    ("Minecraft", "https://namemc.com/profile/{}",
     "https://api.mojang.com/users/profiles/minecraft/{}",
     lambda j: isinstance(j, dict) and "id" in j),
    ("Chess.com", "https://chess.com/member/{}", "https://api.chess.com/pub/player/{}", "status"),
    ("Lichess", "https://lichess.org/@/{}", "https://lichess.org/api/user/{}", "status"),
    ("Speedrun.com", "https://speedrun.com/users/{}", "https://www.speedrun.com/api/v1/users/{}",
     "status"),
    ("itch.io", "https://{}.itch.io", "https://{}.itch.io", "status"),
    ("Hacker News", "https://news.ycombinator.com/user?id={}",
     "https://hacker-news.firebaseio.com/v0/user/{}.json", lambda j: j is not None),
    ("Keybase", "https://keybase.io/{}",
     "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}",
     lambda j: bool(j and j.get("them") and j["them"][0])),
    ("Dev.to", "https://dev.to/{}", "https://dev.to/api/users/by_username?url={}", "status"),
    ("npm", "https://npmjs.com/~{}", "https://www.npmjs.com/~{}", "status"),
    ("Docker Hub", "https://hub.docker.com/u/{}", "https://hub.docker.com/v2/users/{}/", "status"),
    ("Replit", "https://replit.com/@{}", "https://replit.com/@{}", "status"),
    ("SoundCloud", "https://soundcloud.com/{}", "https://soundcloud.com/{}", "status"),
    ("Vimeo", "https://vimeo.com/{}", "https://vimeo.com/{}", "status"),
    ("Pastebin", "https://pastebin.com/u/{}", "https://pastebin.com/u/{}", "status"),
    ("Linktree", "https://linktr.ee/{}", "https://linktr.ee/{}", "status"),
    ("Patreon", "https://patreon.com/{}", "https://www.patreon.com/{}", "status"),
    ("Medium", "https://medium.com/@{}", "https://medium.com/@{}", "status"),
    ("Mastodon", "https://mastodon.social/@{}",
     "https://mastodon.social/api/v1/accounts/lookup?acct={}", "status"),
    ("Bluesky", "https://bsky.app/profile/{}.bsky.social",
     "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={}.bsky.social",
     lambda j: isinstance(j, dict) and "did" in j),
    ("Gravatar", "https://gravatar.com/{}", "https://en.gravatar.com/{}.json", "status"),
    ("Hugging Face", "https://huggingface.co/{}", "https://huggingface.co/api/users/{}/overview",
     "status"),
    ("Scratch", "https://scratch.mit.edu/users/{}", "https://api.scratch.mit.edu/users/{}", "status"),
    ("Wattpad", "https://wattpad.com/user/{}",
     "https://www.wattpad.com/api/v3/users/{}?fields=username", "status"),
    ("MyAnimeList", "https://myanimelist.net/profile/{}", "https://api.jikan.moe/v4/users/{}",
     "status"),
    ("AniList", "https://anilist.co/user/{}", "https://anilist.co/user/{}/", "status"),
    ("Monkeytype", "https://monkeytype.com/profile/{}",
     "https://api.monkeytype.com/users/{}/profile", "status"),
    ("Codeforces", "https://codeforces.com/profile/{}",
     "https://codeforces.com/api/user.info?handles={}",
     lambda j: isinstance(j, dict) and j.get("status") == "OK"),
    ("Duolingo", "https://duolingo.com/profile/{}",
     "https://www.duolingo.com/2017-06-30/users?username={}&fields=users",
     lambda j: isinstance(j, dict) and bool(j.get("users"))),
    ("DeviantArt", "https://deviantart.com/{}", "https://www.deviantart.com/{}", "status"),
    ("SourceForge", "https://sourceforge.net/u/{}/profile", "https://sourceforge.net/u/{}/profile",
     "status"),
    ("Internet Archive", "https://archive.org/details/@{}", "https://archive.org/details/@{}",
     "status"),
    ("Flickr", "https://flickr.com/people/{}", "https://www.flickr.com/people/{}", "status"),
    ("Trakt", "https://trakt.tv/users/{}", "https://trakt.tv/users/{}", "status"),
    ("Newgrounds", "https://{}.newgrounds.com", "https://{}.newgrounds.com", "status"),
    ("Gumroad", "https://{}.gumroad.com", "https://{}.gumroad.com", "status"),
    ("Ko-fi", "https://ko-fi.com/{}", "https://ko-fi.com/{}", "status"),
    ("Buy Me a Coffee", "https://buymeacoffee.com/{}", "https://buymeacoffee.com/{}", "status"),
    ("Roblox DevForum", "https://devforum.roblox.com/u/{}",
     "https://devforum.roblox.com/u/{}.json", lambda j: isinstance(j, dict) and "user" in j),
    ("Kick", "https://kick.com/{}", "https://kick.com/api/v2/channels/{}", "status"),
    ("Letterboxd", "https://letterboxd.com/{}/", "https://letterboxd.com/{}/", "status"),
    ("Tumblr", "https://{}.tumblr.com", "https://{}.tumblr.com", "status"),
]

# Sites that block automated checks — listed as links to verify by hand.
MANUAL = [
    ("Instagram", "https://instagram.com/{}"),
    ("TikTok", "https://tiktok.com/@{}"),
    ("X / Twitter", "https://x.com/{}"),
    ("YouTube", "https://youtube.com/@{}"),
    ("Twitch", "https://twitch.tv/{}"),
    ("Threads", "https://threads.net/@{}"),
    ("Pinterest", "https://pinterest.com/{}"),
    ("Snapchat", "https://snapchat.com/add/{}"),
    ("Telegram", "https://t.me/{}"),
    ("Spotify", "https://open.spotify.com/user/{}"),
]


def check_site(site, username):
    name, profile, url, method = site
    try:
        r = get(url.format(username), allow_redirects=True, timeout=8)
        if r.status_code in (403, 429, 503):
            return name, profile.format(username), None
        head = r.text[:3000].lower()
        if any(s in head for s in ("client challenge", "just a moment", "captcha",
                                   "attention required", "access denied")):
            return name, profile.format(username), None
        if callable(method):
            try:
                j = r.json() if r.status_code == 200 else None
            except Exception:
                j = None
            if r.status_code == 200 and j is None:
                return name, profile.format(username), None
            return name, profile.format(username), bool(method(j)) if r.status_code == 200 else False
        if method == "status":
            if r.status_code == 200:
                return name, profile.format(username), True
            if r.status_code in (404, 410):
                return name, profile.format(username), False
            return name, profile.format(username), None
        if method.startswith("text:"):
            needle = method[5:]
            if r.status_code == 404:
                return name, profile.format(username), False
            return name, profile.format(username), needle not in r.text
    except Exception:
        pass
    return name, profile.format(username), None


# ──────────────────────────────────────────────────────────────────────────────
# Account detail — public profile fields for platforms with open APIs
# ──────────────────────────────────────────────────────────────────────────────
def _ts(v):
    try:
        return datetime.fromtimestamp(int(v)).strftime("%Y-%m-%d")
    except Exception:
        return fmt_date(v) if isinstance(v, str) else None


def d_github(u):
    j = get_json(f"https://api.github.com/users/{u}")
    if not j:
        return None
    repos = get_json(f"https://api.github.com/users/{u}/repos?sort=updated&per_page=8") or []
    return [("Name", j.get("name")), ("Bio", j.get("bio")), ("Company", j.get("company")),
            ("Location", j.get("location")), ("Website", j.get("blog")),
            ("Twitter", j.get("twitter_username")), ("Public repos", j.get("public_repos")),
            ("Gists", j.get("public_gists")), ("Followers", j.get("followers")),
            ("Following", j.get("following")), ("Created", fmt_date(j.get("created_at"))),
            ("Last updated", fmt_date(j.get("updated_at"))),
            ("Recent repos", [f"{r['name']}  ★{r['stargazers_count']}  {r.get('language') or ''}"
                              for r in repos if isinstance(r, dict)])]


def d_gitlab(u):
    j = get_json(f"https://gitlab.com/api/v4/users?username={u}")
    if not j:
        return None
    full = get_json(f"https://gitlab.com/api/v4/users/{j[0]['id']}") or j[0]
    return [("Name", full.get("name")), ("Bio", full.get("bio")),
            ("Location", full.get("location")), ("Website", full.get("website_url")),
            ("Job", full.get("job_title")), ("Organization", full.get("organization")),
            ("Created", fmt_date(full.get("created_at"))), ("State", full.get("state"))]


def d_reddit(u):
    j = get_json(f"https://www.reddit.com/user/{u}/about.json")
    d = (j or {}).get("data")
    if not d:
        return None
    return [("Created", _ts(d.get("created_utc"))), ("Link karma", d.get("link_karma")),
            ("Comment karma", d.get("comment_karma")), ("Verified email", d.get("has_verified_email")),
            ("Moderator", d.get("is_mod")), ("Premium", d.get("is_gold")),
            ("Bio", ((d.get("subreddit") or {}).get("public_description")) or None)]


def d_chess(u):
    j = get_json(f"https://api.chess.com/pub/player/{u}")
    if not j:
        return None
    s = get_json(f"https://api.chess.com/pub/player/{u}/stats") or {}
    ratings = [f"{k.replace('chess_', '')}: {v['last']['rating']}" for k, v in s.items()
               if isinstance(v, dict) and "last" in v]
    return [("Name", j.get("name")), ("Title", j.get("title")),
            ("Country", (j.get("country") or "").rsplit("/", 1)[-1] or None),
            ("Joined", _ts(j.get("joined"))), ("Last online", _ts(j.get("last_online"))),
            ("Followers", j.get("followers")), ("Status", j.get("status")), ("Ratings", ratings)]


def d_lichess(u):
    j = get_json(f"https://lichess.org/api/user/{u}")
    if not j:
        return None
    p = j.get("profile", {})
    perfs = [f"{k}: {v['rating']}" for k, v in (j.get("perfs") or {}).items()
             if isinstance(v, dict) and v.get("games")]
    return [("Bio", p.get("bio")), ("Real name", p.get("realName")),
            ("Country", p.get("flag") or p.get("country")), ("Links", p.get("links")),
            ("Created", _ts((j.get("createdAt") or 0) // 1000)),
            ("Last seen", _ts((j.get("seenAt") or 0) // 1000)),
            ("Games", (j.get("count") or {}).get("all")), ("Ratings", perfs)]


def d_hn(u):
    j = get_json(f"https://hacker-news.firebaseio.com/v0/user/{u}.json")
    if not j:
        return None
    return [("Created", _ts(j.get("created"))), ("Karma", j.get("karma")),
            ("Submissions", len(j.get("submitted", []))),
            ("About", re.sub("<[^>]+>", " ", j.get("about") or "").strip() or None)]


def d_keybase(u):
    j = get_json(f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}")
    them = ((j or {}).get("them") or [None])[0]
    if not them:
        return None
    prof = them.get("profile") or {}
    proofs = [f"{p.get('proof_type')}: {p.get('nametag')}"
              for p in ((them.get("proofs_summary") or {}).get("all") or [])]
    return [("Name", prof.get("full_name")), ("Bio", prof.get("bio")),
            ("Location", prof.get("location")), ("Verified proofs", proofs)]


def d_mastodon(u):
    j = get_json(f"https://mastodon.social/api/v1/accounts/lookup?acct={u}")
    if not j:
        return None
    return [("Display name", j.get("display_name")),
            ("Bio", re.sub("<[^>]+>", " ", j.get("note") or "").strip() or None),
            ("Created", fmt_date(j.get("created_at"))), ("Posts", j.get("statuses_count")),
            ("Followers", j.get("followers_count")), ("Following", j.get("following_count")),
            ("Last post", j.get("last_status_at")),
            ("Fields", [f"{f['name']}: {re.sub('<[^>]+>', '', f['value'])}"
                        for f in j.get("fields", [])])]


def d_bluesky(u):
    j = get_json("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
                 f"?actor={u}.bsky.social")
    if not j:
        return None
    return [("Display name", j.get("displayName")), ("Bio", j.get("description")),
            ("DID", j.get("did")), ("Created", fmt_date(j.get("createdAt"))),
            ("Posts", j.get("postsCount")), ("Followers", j.get("followersCount")),
            ("Following", j.get("followsCount"))]


def d_devto(u):
    j = get_json(f"https://dev.to/api/users/by_username?url={u}")
    if not j:
        return None
    return [("Name", j.get("name")), ("Bio", j.get("summary")), ("Location", j.get("location")),
            ("Website", j.get("website_url")), ("GitHub", j.get("github_username")),
            ("Twitter", j.get("twitter_username")), ("Joined", j.get("joined_at"))]


def d_dockerhub(u):
    j = get_json(f"https://hub.docker.com/v2/users/{u}/")
    if not j:
        return None
    return [("Name", j.get("full_name")), ("Company", j.get("company")),
            ("Location", j.get("location")), ("Website", j.get("profile_url")),
            ("Joined", fmt_date(j.get("date_joined")))]


def d_minecraft(u):
    j = get_json(f"https://api.mojang.com/users/profiles/minecraft/{u}")
    if not j:
        return None
    return [("UUID", j.get("id")), ("Name", j.get("name")),
            ("Skin", f"https://mc-heads.net/body/{j.get('id')}")]


def d_speedrun(u):
    j = (get_json(f"https://www.speedrun.com/api/v1/users/{u}") or {}).get("data")
    if not j:
        return None
    loc = ((j.get("location") or {}).get("country") or {}).get("names", {}).get("international")
    return [("Role", j.get("role")), ("Signed up", fmt_date(j.get("signup"))), ("Country", loc),
            ("Twitch", (j.get("twitch") or {}).get("uri")),
            ("YouTube", (j.get("youtube") or {}).get("uri"))]


def d_codeberg(u):
    j = get_json(f"https://codeberg.org/api/v1/users/{u}")
    if not j:
        return None
    return [("Name", j.get("full_name")), ("Bio", j.get("description")),
            ("Location", j.get("location")), ("Website", j.get("website")),
            ("Created", fmt_date(j.get("created"))), ("Followers", j.get("followers_count"))]


def d_kick(u):
    j = get_json(f"https://kick.com/api/v2/channels/{u}")
    if not j:
        return None
    usr = j.get("user") or {}
    return [("Bio", usr.get("bio")), ("Followers", j.get("followers_count")),
            ("Verified", j.get("verified")), ("Live now", bool(j.get("livestream"))),
            ("Socials", [f"{k}: {usr[k]}" for k in ("instagram", "twitter", "youtube",
                                                    "discord", "tiktok") if usr.get(k)])]


def d_steam(u):
    try:
        r = get(f"https://steamcommunity.com/id/{u}?xml=1")
        if not r.ok or "<steamID64>" not in r.text:
            return None
        g = lambda tag: (re.search(rf"<{tag}>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{tag}>", r.text, re.S)
                         or [None, None])[1]
        return [("SteamID64", g("steamID64")), ("Display name", g("steamID")),
                ("Real name", g("realname")), ("Location", g("location")),
                ("Member since", g("memberSince")), ("Privacy", g("privacyState")),
                ("Status", g("onlineState")), ("VAC banned", g("vacBanned")),
                ("Summary", re.sub("<[^>]+>", " ", g("summary") or "").strip() or None)]
    except Exception:
        return None


def d_hf(u):
    j = get_json(f"https://huggingface.co/api/users/{u}/overview")
    if not j:
        return None
    return [("Name", j.get("fullname")), ("Created", fmt_date(j.get("createdAt"))),
            ("Models", j.get("numModels")), ("Datasets", j.get("numDatasets")),
            ("Spaces", j.get("numSpaces")), ("Followers", j.get("numFollowers")),
            ("Orgs", [o.get("name") for o in j.get("orgs", [])])]


def d_scratch(u):
    j = get_json(f"https://api.scratch.mit.edu/users/{u}")
    if not j:
        return None
    p = j.get("profile", {})
    return [("Joined", fmt_date((j.get("history") or {}).get("joined"))),
            ("Country", p.get("country")), ("About me", p.get("bio")),
            ("Working on", p.get("status"))]


def d_mal(u):
    j = (get_json(f"https://api.jikan.moe/v4/users/{u}") or {}).get("data")
    if not j:
        return None
    return [("Joined", fmt_date(j.get("joined"))), ("Last online", fmt_date(j.get("last_online"))),
            ("Location", j.get("location"))]


def d_monkeytype(u):
    j = (get_json(f"https://api.monkeytype.com/users/{u}/profile") or {}).get("data")
    if not j:
        return None
    pb = (j.get("personalBests") or {}).get("time", {})
    best = []
    for secs in ("15", "60"):
        runs = pb.get(secs) or []
        if runs:
            best.append(f"{secs}s: {max(r.get('wpm', 0) for r in runs):.0f} wpm")
    return [("Joined", _ts((j.get("addedAt") or 0) // 1000)),
            ("Tests completed", (j.get("typingStats") or {}).get("completedTests")),
            ("Best", best), ("Bio", (j.get("details") or {}).get("bio"))]


def d_codeforces(u):
    j = get_json(f"https://codeforces.com/api/user.info?handles={u}")
    if not j or j.get("status") != "OK":
        return None
    r = j["result"][0]
    return [("Rank", r.get("rank")), ("Rating", r.get("rating")), ("Max rating", r.get("maxRating")),
            ("Country", r.get("country")), ("Organization", r.get("organization")),
            ("Registered", _ts(r.get("registrationTimeSeconds")))]


def d_duolingo(u):
    j = get_json(f"https://www.duolingo.com/2017-06-30/users?username={u}")
    users = (j or {}).get("users") or []
    if not users:
        return None
    x = users[0]
    return [("Name", x.get("name")), ("Streak", x.get("streak")), ("Total XP", x.get("totalXp")),
            ("Joined", _ts(x.get("creationDate"))),
            ("Learning", [c.get("title") for c in x.get("courses", [])])]


def d_devforum(u):
    j = (get_json(f"https://devforum.roblox.com/u/{u}.json") or {}).get("user")
    if not j:
        return None
    return [("Name", j.get("name")), ("Title", j.get("title")), ("Trust level", j.get("trust_level")),
            ("Joined", fmt_date(j.get("created_at"))), ("Last posted", fmt_date(j.get("last_posted_at"))),
            ("Badges", j.get("badge_count")), ("Profile views", j.get("profile_view_count"))]


DETAIL = {
    "Hugging Face": d_hf, "Scratch": d_scratch, "MyAnimeList": d_mal, "Monkeytype": d_monkeytype,
    "Codeforces": d_codeforces, "Duolingo": d_duolingo, "Roblox DevForum": d_devforum,
    "GitHub": d_github, "GitLab": d_gitlab, "Reddit": d_reddit, "Chess.com": d_chess,
    "Lichess": d_lichess, "Hacker News": d_hn, "Keybase": d_keybase, "Mastodon": d_mastodon,
    "Bluesky": d_bluesky, "Dev.to": d_devto, "Docker Hub": d_dockerhub,
    "Minecraft": d_minecraft, "Speedrun.com": d_speedrun, "Codeberg": d_codeberg,
    "Kick": d_kick, "Steam": d_steam,
}


def _safe_detail(fn, u):
    try:
        return fn(u)
    except Exception:
        return None


def lookup_username(username: str) -> dict:
    username = username.strip().lstrip("@")
    section(f"username · {username}")
    results = []
    with console.status(f"[dim]checking {len(SITES)} platforms…", spinner="line"):
        with ThreadPoolExecutor(16) as ex:
            futs = [ex.submit(check_site, s, username) for s in SITES]
            for f in as_completed(futs):
                results.append(f.result())
    order = {True: 0, None: 1, False: 2}
    results.sort(key=lambda x: (order[x[2]], x[0].lower()))

    t = Table(box=box.SIMPLE_HEAD, header_style="label", border_style="rule",
              padding=(0, 2, 0, 1))
    t.add_column("Platform", style="value")
    t.add_column("Status")
    t.add_column("Profile", style="dim", overflow="fold")
    for name, url, found in results:
        if found is True:
            t.add_row(name, Text("FOUND", style="hit"), Text(url, style="value"))
        elif found is None:
            t.add_row(name, Text("unverified", style="warn"), url)
    console.print(t)
    found_n = sum(1 for r in results if r[2] is True)
    unk_n = sum(1 for r in results if r[2] is None)
    none_n = sum(1 for r in results if r[2] is False)
    console.print(Text(f"  {found_n} found  ·  {unk_n} unverified  ·  {none_n} not found",
                       style="label"))
    # Detailed public profiles for every found account that has an open API
    hits = [n for n, _, f in results if f is True and n in DETAIL]
    details = {}
    if hits:
        with console.status(f"[dim]pulling {len(hits)} public profiles…", spinner="line"):
            with ThreadPoolExecutor(8) as ex:
                futs = {ex.submit(_safe_detail, DETAIL[n], username): n for n in hits}
                for f in as_completed(futs):
                    if f.result():
                        details[futs[f]] = f.result()
        for name in hits:
            if name in details:
                section(f"{name} · {username}")
                kv_table(details[name])

    console.print(Text("\n  Check manually (these block automated lookups)", style="label"))
    kv_table([(n, u.format(username)) for n, u in MANUAL])
    note("A matching username on two sites does not mean it's the same person.")
    return {"type": "username", "query": username,
            "results": [{"site": n, "url": u, "found": f} for n, u, f in results],
            "details": {k: dict((a, b) for a, b in v) for k, v in details.items()}}


# ──────────────────────────────────────────────────────────────────────────────
# Roblox
# ──────────────────────────────────────────────────────────────────────────────
def roblox_resolve(q: str) -> int | None:
    if q.isdigit():
        return int(q)
    try:
        r = session.post("https://users.roblox.com/v1/usernames/users",
                         json={"usernames": [q], "excludeBannedUsers": False},
                         timeout=TIMEOUT)
        data = r.json().get("data", [])
        return data[0]["id"] if data else None
    except Exception:
        return None


def lookup_roblox(q: str) -> dict:
    q = q.strip().lstrip("@")
    section(f"roblox · {q}")
    with console.status("[dim]querying Roblox public APIs…", spinner="line"):
        uid = roblox_resolve(q)
        if uid is None:
            note("no Roblox account with that username")
            return {"type": "roblox", "query": q, "found": False}
        base = f"https://users.roblox.com/v1/users/{uid}"
        urls = {
            "user": base,
            "history": f"{base}/username-history?limit=50&sortOrder=Desc",
            "friends": f"https://friends.roblox.com/v1/users/{uid}/friends/count",
            "followers": f"https://friends.roblox.com/v1/users/{uid}/followers/count",
            "following": f"https://friends.roblox.com/v1/users/{uid}/followings/count",
            "groups": f"https://groups.roblox.com/v2/users/{uid}/groups/roles",
            "badges": f"https://badges.roblox.com/v1/users/{uid}/badges?limit=10&sortOrder=Desc",
            "games": f"https://games.roblox.com/v2/users/{uid}/games?accessFilter=Public&limit=10&sortOrder=Desc",
            "rolimons": f"https://api.rolimons.com/players/v1/playerinfo/{uid}",
            "thumb": ("https://thumbnails.roblox.com/v1/users/avatar-headshot"
                      f"?userIds={uid}&size=420x420&format=Png"),
        }
        with ThreadPoolExecutor(8) as ex:
            res = dict(zip(urls, ex.map(get_json, urls.values())))

    u = res["user"] or {}
    if not u:
        note("user ID not found (may be terminated or invalid)")
        return {"type": "roblox", "query": q, "id": uid, "found": False}
    created = fmt_date(u.get("created"))
    age = None
    if u.get("created"):
        try:
            d = datetime.fromisoformat(u["created"].replace("Z", "+00:00"))
            age = f"{(datetime.now(d.tzinfo) - d).days:,} days"
        except Exception:
            pass
    history = [h["name"] for h in (res["history"] or {}).get("data", [])]
    groups = (res["groups"] or {}).get("data", [])
    badges = (res["badges"] or {}).get("data", [])
    games = [{"name": g.get("name"), "visits": g.get("placeVisits"),
              "url": f"https://www.roblox.com/games/{(g.get('rootPlace') or {}).get('id')}"}
             for g in (res["games"] or {}).get("data", [])]
    roli = res["rolimons"] or {}
    trading = {"value": roli.get("value"), "rap": roli.get("rap"), "rank": roli.get("rank"),
               "premium": roli.get("premium"), "terminated": roli.get("terminated"),
               "rolimons": f"https://www.rolimons.com/player/{uid}"} if roli.get("success") else None
    thumb = ((res["thumb"] or {}).get("data") or [{}])[0].get("imageUrl")

    kv_table([
        ("User ID", uid),
        ("Username", u.get("name")),
        ("Display name", u.get("displayName")),
        ("Created", f"{created}  ({age} old)" if age else created),
        ("Banned", "yes" if u.get("isBanned") else "no"),
        ("Verified badge", "yes" if u.get("hasVerifiedBadge") else "no"),
        ("Friends", (res["friends"] or {}).get("count")),
        ("Followers", (res["followers"] or {}).get("count")),
        ("Following", (res["following"] or {}).get("count")),
        ("Bio", (u.get("description") or "").strip() or None),
        ("Profile", f"https://www.roblox.com/users/{uid}/profile"),
        ("Avatar", thumb),
    ])
    console.print(Text(f"\n  Previous usernames ({len(history)})", style="label"))
    if history:
        kv_table([("", ", ".join(history))])
    else:
        note("none")
    console.print(Text(f"\n  Groups ({len(groups)})", style="label"))
    if groups:
        list_table(["Group", "Role", "Members", "ID"],
                   [[g["group"]["name"], g["role"]["name"], f"{g['group'].get('memberCount', 0):,}",
                     g["group"]["id"]] for g in groups[:25]])
        if len(groups) > 25:
            note(f"+{len(groups)-25} more")
    else:
        note("none, or inventory/groups hidden")
    console.print(Text("\n  Recent badges", style="label"))
    if badges:
        list_table(["Badge", "Awarded in"],
                   [[b.get("name"), (b.get("awarder") or {}).get("id")] for b in badges])
    else:
        note("none visible")
    console.print(Text(f"\n  Created games ({len(games)})", style="label"))
    if games:
        list_table(["Game", "Visits"], [[g["name"], f"{g['visits'] or 0:,}"] for g in games])
    else:
        note("none public")
    if trading:
        console.print(Text("\n  Trading (Rolimons)", style="label"))
        kv_table([(k.title(), v) for k, v in trading.items()])
    return {"type": "roblox", "query": q, "id": uid, "user": u, "games": games, "trading": trading,
            "previous_usernames": history,
            "groups": [{"name": g["group"]["name"], "id": g["group"]["id"],
                        "role": g["role"]["name"]} for g in groups],
            "badges": [b.get("name") for b in badges], "avatar": thumb}


# ──────────────────────────────────────────────────────────────────────────────
# Auto-detect
# ──────────────────────────────────────────────────────────────────────────────
DOMAIN_RE = re.compile(r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/.*)?$", re.I)


def detect(q: str) -> str:
    q = q.strip()
    try:
        ipaddress.ip_address(q)
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.match(q):
        return "email"
    if DOMAIN_RE.match(q):
        return "domain"
    if q.isdigit():
        return "roblox"
    return "user"


def run(kind: str, q: str) -> list[dict]:
    out = []
    if kind == "domain":
        d = lookup_domain(q)
        out.append(d)
        for ip in d.pop("_ips", [])[:2]:
            out.append(lookup_ip(ip))
    elif kind == "ip":
        out.append(lookup_ip(q))
    elif kind == "email":
        out.append(lookup_email(q))
    elif kind == "roblox":
        out.append(lookup_roblox(q))
    elif kind == "user":
        out.append(lookup_roblox(q))
        out.append(lookup_username(q))
    elif kind == "auto":
        return run(detect(q), q)
    return out


def save_json(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    console.print(Text(f"\n  saved → {path}", style="label"))


HELP = """[label]Commands[/]
  [value]<anything>[/]           auto-detect: email, IP, domain, Roblox ID, or username
  [value]domain[/] <name>        registration, DNS, web server, subdomains
  [value]ip[/] <address>         ASN, network owner, approximate location, reverse DNS
  [value]email[/] <address>      mail servers, provider type, public Gravatar profile
  [value]user[/] <name>          Roblox + 30-ish platforms
  [value]roblox[/] <name|id>     full Roblox profile, past names, groups, badges
  [value]save[/] <file.json>     save the last result
  [value]help[/] · [value]clear[/] · [value]exit[/]"""


def interactive():
    banner()
    console.print(Panel(HELP, box=box.SQUARE, border_style="rule", padding=(1, 2)))
    last = []
    while True:
        try:
            line = console.input("\n[title]›[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        cmd = cmd.lower()
        if cmd in ("exit", "quit", "q"):
            break
        if cmd == "help":
            console.print(HELP)
            continue
        if cmd == "clear":
            console.clear()
            banner()
            continue
        if cmd == "save":
            if last and arg:
                save_json(last, arg.strip())
            else:
                note("nothing to save, or no filename given")
            continue
        t0 = time.time()
        if cmd in ("domain", "ip", "email", "user", "roblox") and arg:
            last = run(cmd, arg.strip())
        else:
            last = run("auto", line)
        console.print(Text(f"\n  done in {time.time()-t0:.1f}s", style="dim"))


def main():
    p = argparse.ArgumentParser(prog="lookup", description="Open-source intelligence lookup.")
    p.add_argument("args", nargs="*", help="[type] query   (type: domain, ip, email, user, roblox)")
    p.add_argument("--json", metavar="FILE", help="save raw results to a JSON file")
    a = p.parse_args()
    if not a.args:
        interactive()
        return
    if a.args[0].lower() in ("domain", "ip", "email", "user", "roblox") and len(a.args) > 1:
        kind, q = a.args[0].lower(), " ".join(a.args[1:])
    else:
        kind, q = "auto", " ".join(a.args)
    banner()
    t0 = time.time()
    results = run(kind, q)
    console.print(Text(f"\n  done in {time.time()-t0:.1f}s", style="dim"))
    if a.json:
        save_json(results, a.json)
    console.print()


if __name__ == "__main__":
    main()
