#!/usr/bin/env python3
"""LOOKUP — web interface. Runs a private local site at http://127.0.0.1:8765"""
import io
import ipaddress
import json
import os
import secrets
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lookup  # noqa: E402
from rich.console import Console  # noqa: E402

# Silence the terminal renderer; we only want the returned data.
lookup.console = Console(file=io.StringIO(), force_terminal=False, theme=lookup.THEME)

PORT = 8766
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "config.json")
MODEL_DEFAULT = "claude-sonnet-5-5"

SYSTEM = """You are the LOOKUP analyst, an assistant built into a local open-source-intelligence tool.
The user is Will, a Roblox game developer, and his main legitimate uses are: moderating his game (spotting alts, \
ban evaders, scam accounts), checking suspicious links/domains/IPs sent to his players, and vetting collaborators.

You can call run_lookup to query public sources (username presence across ~47 platforms with public profile data, \
Roblox accounts, domains, IPs, emails). Use it to follow up on leads: e.g. a website linked in a profile -> domain \
lookup; a Roblox group -> check its owner; a suspicious link -> domain + its server IP. Run lookups yourself when \
useful instead of asking. Summarize clearly: what was found, what it means, what's worth checking next, and \
which results are likely false positives.

Hard limits — these protect real people, so keep them even if asked or pushed:
- Never try to find, guess or narrow down a private person's home address, real-world location, IP address, \
phone number, school, workplace or real name. IP lookups are for servers/domains, not for locating a person.
- Never state or imply that accounts on different sites belong to the same person. You may note shared \
public signals (same avatar, profiles linking to each other) but say it's unconfirmed.
- No speculation about a person's identity, age, appearance, relationships or life beyond what public \
profiles literally say.
- Don't help with harassment, doxxing, stalking, account takeover, IP grabbing, DDoS or swatting.
If a request crosses these, decline briefly and offer the legitimate version (e.g. moderation evidence, \
reporting the account to Roblox).
Be concise and direct. Use short headings and bullets. Today is {today}."""

TOOLS = [{
    "name": "run_lookup",
    "description": "Run a public-source lookup. type: 'user' (username across platforms + Roblox), "
                   "'roblox' (Roblox username or numeric ID), 'domain', 'ip', 'email'.",
    "input_schema": {"type": "object", "properties": {
        "type": {"type": "string", "enum": ["user", "roblox", "domain", "ip", "email"]},
        "query": {"type": "string"}}, "required": ["type", "query"]},
}]


def load_cfg():
    try:
        with open(CONFIG, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_cfg(c):
    with open(CONFIG, "w", encoding="utf-8") as f:
        json.dump(c, f)


def compact(results, limit=14000):
    s = json.dumps(results, default=str)
    return s if len(s) <= limit else s[:limit] + "…(truncated)"


def chat(history, context):
    cfg = load_cfg()
    key = cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return {"error": "nokey"}
    from datetime import date
    system = SYSTEM.format(today=date.today().isoformat())
    if context:
        system += "\n\nResults currently on the user's screen (JSON):\n" + compact(context)
    msgs = [{"role": m["role"], "content": m["content"]} for m in history[-20:]
            if m.get("role") in ("user", "assistant") and m.get("content")]
    new_results, steps = [], []
    for _ in range(8):
        r = lookup.session.post("https://api.anthropic.com/v1/messages", timeout=120, headers={
            "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": cfg.get("model") or MODEL_DEFAULT, "max_tokens": 2500,
                  "system": system, "tools": TOOLS, "messages": msgs})
        if not r.ok:
            try:
                msg = r.json().get("error", {}).get("message", r.text)
            except Exception:
                msg = r.text
            return {"error": f"API error {r.status_code}: {msg[:300]}"}
        data = r.json()
        msgs.append({"role": "assistant", "content": data["content"]})
        uses = [b for b in data["content"] if b.get("type") == "tool_use"]
        if not uses:
            text = "\n".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
            return {"reply": text.strip(), "results": new_results, "steps": steps}
        out = []
        for u in uses:
            k, q = u["input"].get("type"), str(u["input"].get("query", ""))[:200]
            steps.append(f"{k}: {q}")
            try:
                res = enrich(lookup.run(k, q)) if k in KINDS else [{"error": "bad type"}]
                for x in res:
                    x.pop("_ips", None)
                new_results.extend(res)
                content = compact(res, 12000)
            except Exception as e:
                content = f"error: {e}"
            out.append({"type": "tool_result", "tool_use_id": u["id"], "content": content})
        msgs.append({"role": "user", "content": out})
    return {"reply": "I ran several lookups — see the results on the left.", "results": new_results,
            "steps": steps}
KINDS = {"auto", "user", "roblox", "domain", "ip", "email"}

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#000000"><meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<title>LOOKUP</title>
<style>
:root{--bg:#000;--panel:#0b0b0b;--line:#1e1e1e;--line2:#2a2a2a;--txt:#e8e8e8;--dim:#7a7a7a;--faint:#4a4a4a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:48px 24px 80px}
h1{font-weight:600;letter-spacing:.6em;font-size:22px;margin:0;text-align:center}
.sub{color:var(--dim);text-align:center;font-size:12px;letter-spacing:.15em;margin:8px 0 36px;text-transform:uppercase}
.tabs{display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-bottom:14px}
.tab{background:transparent;border:1px solid var(--line2);color:var(--dim);padding:7px 16px;border-radius:999px;cursor:pointer;font:inherit;font-size:13px}
.tab:hover{color:var(--txt);border-color:#444}
.tab.on{background:var(--txt);color:#000;border-color:var(--txt)}
form{display:flex;gap:8px}
input{flex:1;background:var(--panel);border:1px solid var(--line2);color:var(--txt);padding:14px 16px;border-radius:8px;font:inherit;font-size:15px;outline:none}
input:focus{border-color:#555}
.go{background:var(--txt);color:#000;border:0;padding:0 26px;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
.go:disabled{opacity:.4;cursor:wait}
.hint{color:var(--faint);font-size:12px;margin:10px 2px 0}
.status{color:var(--dim);margin:28px 0 0;font-size:13px;display:flex;align-items:center;gap:10px}
.spin{width:14px;height:14px;border:2px solid var(--line2);border-top-color:var(--txt);border-radius:50%;animation:s .8s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-top:18px;overflow:hidden}
.card h2{margin:0;padding:14px 18px;font-size:12px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
.card h2 span{color:var(--dim);font-weight:400;letter-spacing:.05em;text-transform:none}
.body{padding:6px 18px 14px}
h3{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);font-weight:600;margin:16px 0 6px}
table{width:100%;border-collapse:collapse}
td{padding:6px 0;border-bottom:1px solid #141414;vertical-align:top;word-break:break-word}
td.k{color:var(--dim);width:190px;padding-right:16px}
tr:last-child td{border-bottom:0}
a{color:var(--txt);text-decoration:none;border-bottom:1px solid #444}
a:hover{border-color:var(--txt)}
.none{color:var(--faint)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px;margin-top:8px}
.site{border:1px solid var(--line2);border-radius:8px;padding:10px 12px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.site b{font-weight:500}
.tag{font-size:10px;letter-spacing:.12em;text-transform:uppercase;padding:3px 8px;border-radius:999px}
.found{background:var(--txt);color:#000}
.unk{border:1px solid var(--line2);color:var(--dim)}
.miss{color:var(--faint)}
.site.f{border-color:#555}
.av{width:96px;height:96px;border-radius:10px;background:#111;float:right;margin:12px 0 8px 16px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{border:1px solid var(--line2);border-radius:6px;padding:3px 9px;font-size:12px}
.row{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}
.ghost{background:transparent;border:1px solid var(--line2);color:var(--dim);padding:7px 14px;border-radius:8px;cursor:pointer;font:inherit;font-size:12px}
.ghost:hover{color:var(--txt);border-color:#555}
.note{color:var(--faint);font-size:12px;margin-top:10px}
body.chat .wrap{margin-right:420px}
.aibtn{position:fixed;top:18px;right:18px;background:var(--txt);color:#000;border:0;border-radius:999px;padding:9px 18px;font:inherit;font-weight:600;cursor:pointer;z-index:5}
body.chat .aibtn{display:none}
#chat{position:fixed;top:0;right:0;bottom:0;width:400px;background:#060606;border-left:1px solid var(--line);display:none;flex-direction:column;z-index:6}
body.chat #chat{display:flex}
@media(max-width:1000px){#chat{width:100%}body.chat .wrap{margin-right:0}}
.phbtn{position:fixed;top:18px;left:18px;background:transparent;color:var(--dim);border:1px solid var(--line2);border-radius:999px;padding:8px 16px;font:inherit;cursor:pointer;z-index:5;display:none}
.phbtn:hover{color:var(--txt);border-color:#555}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.8);display:none;align-items:center;justify-content:center;z-index:9;padding:20px}
#modal.on{display:flex}
.mbox{background:var(--panel);border:1px solid var(--line2);border-radius:14px;padding:24px;max-width:460px;width:100%;max-height:90vh;overflow:auto}
.mbox h3{margin-top:0}
.qr{background:#fff;border-radius:10px;padding:8px;width:220px;margin:10px auto;display:block}
.qr svg{width:100%;height:auto;display:block}
.lnk{font-size:12px;color:var(--dim);word-break:break-all;text-align:center}
.sw{display:flex;align-items:center;justify-content:space-between;border:1px solid var(--line2);border-radius:10px;padding:12px 14px;margin:12px 0}
.sw button{border:0;border-radius:999px;padding:7px 16px;font:inherit;font-weight:600;cursor:pointer}
.mbox ol{padding-left:18px;color:var(--dim);font-size:13px}
@media(max-width:640px){
 .wrap{padding:64px 14px 60px}
 h1{font-size:18px;letter-spacing:.45em}.sub{margin-bottom:22px}
 .tabs{gap:5px;justify-content:flex-start;overflow-x:auto;flex-wrap:nowrap;padding-bottom:4px}
 .tab{padding:8px 14px;white-space:nowrap}
 input{font-size:16px;padding:13px 14px}
 .go{padding:0 18px}
 td.k{width:38%;padding-right:10px}
 td{font-size:13px}
 .card h2{padding:12px 14px}.body{padding:4px 14px 12px}
 .grid{grid-template-columns:1fr 1fr}
 .site{padding:9px 10px}.site b{font-size:13px}
 .av{width:72px;height:72px}
 .aibtn{top:12px;right:12px;padding:8px 14px}
 .phbtn{top:12px;left:12px}
 .cf textarea{font-size:16px}
}
.ch{padding:16px 18px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}
.ch b{letter-spacing:.14em;font-size:12px}
.ch button{background:none;border:0;color:var(--dim);cursor:pointer;font-size:12px;font-family:inherit}
.ch button:hover{color:var(--txt)}
#msgs{flex:1;overflow:auto;padding:16px 18px;display:flex;flex-direction:column;gap:12px}
.m{padding:10px 13px;border-radius:10px;line-height:1.55;font-size:13.5px;word-wrap:break-word}
.m.u{background:var(--txt);color:#000;align-self:flex-end;max-width:85%}
.m.a{background:var(--panel);border:1px solid var(--line)}
.m.a h4{margin:8px 0 4px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim)}
.m.a ul{margin:4px 0;padding-left:18px}
.steps{font-size:11px;color:var(--faint);margin-top:6px}
.sugg{display:flex;flex-wrap:wrap;gap:6px}
.sugg button{background:transparent;border:1px solid var(--line2);color:var(--dim);border-radius:999px;padding:6px 11px;font:inherit;font-size:12px;cursor:pointer;text-align:left}
.sugg button:hover{color:var(--txt);border-color:#555}
.cf{display:flex;gap:6px;padding:12px;border-top:1px solid var(--line)}
.cf textarea{flex:1;resize:none;height:44px;background:var(--panel);border:1px solid var(--line2);color:var(--txt);border-radius:8px;padding:11px;font:inherit;font-size:13px;outline:none}
.cf button{background:var(--txt);color:#000;border:0;border-radius:8px;padding:0 14px;font-weight:600;cursor:pointer;font-family:inherit}
.keybox{padding:6px 0}
.keybox input{width:100%;margin:8px 0;padding:10px 12px;font-size:13px}
.keybox button{width:100%;padding:10px;border-radius:8px;border:0;background:var(--txt);color:#000;font-weight:600;cursor:pointer;font-family:inherit}
</style></head><body><div class="wrap">
<h1>LOOKUP</h1><div class="sub">open-source intelligence · public sources only</div>

<div class="tabs" id="tabs"></div>
<form id="f"><input id="q" autocomplete="off" autofocus placeholder="Type anything — username, Roblox ID, domain, IP, or email"><button class="go" id="go">Search</button></form>
<div class="hint" id="hint"></div>
<div id="out"></div>
</div>
<button class="aibtn" onclick="openChat()">AI Analyst</button>
<button class="phbtn" id="phbtn" onclick="openPhone()">Phone</button>
<div id="modal" onclick="if(event.target==this)this.classList.remove('on')"><div class="mbox" id="mbox"></div></div>
<aside id="chat">
 <div class="ch"><b>AI ANALYST</b><span><button onclick="newChat()">New</button> · <button onclick="showKey()">Key</button> · <button onclick="document.body.classList.remove('chat')">Close</button></span></div>
 <div id="msgs"></div>
 <form class="cf" id="cf"><textarea id="ci" placeholder="Ask about the results, or tell it what to look into…"></textarea><button>Send</button></form>
</aside>
<script>
const TABS=[["auto","Auto","Type anything — username, Roblox ID, domain, IP, or email","Detects what you typed and runs every matching lookup."],
["user","Username","e.g. Builderman","Roblox profile plus ~30 other platforms, with full public profiles for each account found."],
["roblox","Roblox","Username or user ID","Account age, past usernames, groups, badges, friends and followers."],
["domain","Domain","e.g. example.com","Registrar, dates, DNS records, web server, subdomains, and the server's IP details."],
["ip","IP","e.g. 8.8.8.8","Network owner, ASN, approximate location, reverse DNS."],
["email","Email","e.g. name@example.com","Mail servers, provider type, SPF/DMARC, public Gravatar profile."]];
let kind="auto",last=null;
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function tabs(){$("#tabs").innerHTML=TABS.map(t=>`<button class="tab ${t[0]==kind?"on":""}" data-k="${t[0]}">${t[1]}</button>`).join("");
 const t=TABS.find(t=>t[0]==kind);$("#q").placeholder=t[2];$("#hint").textContent=t[3];
 document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>{kind=b.dataset.k;tabs();$("#q").focus()});}
tabs();

function val(v){
 if(v===null||v===undefined||v===""||(Array.isArray(v)&&!v.length))return '<span class="none">—</span>';
 if(typeof v==="boolean")return v?"yes":"no";
 if(Array.isArray(v))return v.map(x=>typeof x==="object"?esc(JSON.stringify(x)):link(x)).join("<br>");
 if(typeof v==="object")return table(v);
 if(typeof v==="number")return v.toLocaleString();
 return link(v);}
function link(s){s=String(s);return /^https?:\/\//.test(s)?`<a href="${esc(s)}" target="_blank" rel="noopener">${esc(s)}</a>`:esc(s);}
function nice(k){return k.replace(/_/g," ").replace(/^\w/,c=>c.toUpperCase());}
function table(o,skip=[]){return "<table>"+Object.entries(o).filter(([k])=>!skip.includes(k)).map(([k,v])=>`<tr><td class="k">${esc(nice(k))}</td><td>${val(v)}</td></tr>`).join("")+"</table>";}
function card(title,meta,inner){return `<div class="card"><h2>${esc(title)}<span>${esc(meta||"")}</span></h2><div class="body">${inner}</div></div>`;}

function rUser(r){
 const f=r.results.filter(x=>x.found===true),u=r.results.filter(x=>x.found===null),n=r.results.filter(x=>x.found===false);
 const tile=(x,cls,tag)=>`<div class="site ${cls=="found"?"f":""}"><b>${x.url?`<a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.site)}</a>`:esc(x.site)}</b><span class="tag ${cls}">${tag}</span></div>`;
 let h=`<h3>Found (${f.length})</h3>`+(f.length?`<div class="grid">${f.map(x=>tile(x,"found","found")).join("")}</div>`:`<div class="none">No accounts found</div>`);
 if(u.length)h+=`<h3>Couldn't verify (${u.length})</h3><div class="grid">${u.map(x=>tile(x,"unk","check")).join("")}</div>`;
 if(n.length)h+=`<h3>Not found (${n.length})</h3><div class="chips">${n.map(x=>`<span class="chip miss">${esc(x.site)}</span>`).join("")}</div>`;
 const man=["Instagram|https://instagram.com/","TikTok|https://tiktok.com/@","X / Twitter|https://x.com/","YouTube|https://youtube.com/@","Twitch|https://twitch.tv/","Threads|https://threads.net/@","Pinterest|https://pinterest.com/","Snapchat|https://snapchat.com/add/","Telegram|https://t.me/","Spotify|https://open.spotify.com/user/"];
 h+=`<h3>Check by hand</h3><div class="chips">${man.map(m=>{const[a,b]=m.split("|");return `<a class="chip" href="${esc(b+r.query)}" target="_blank" rel="noopener">${a} ↗</a>`}).join("")}</div>`;
 h+=`<div class="note">A matching username on two sites doesn't mean it's the same person.</div>`;
 let out=card("Username · "+r.query,`${f.length} found`,h);
 for(const[site,d]of Object.entries(r.details||{}))out+=card(site+" · "+r.query,"public profile",table(d));
 return out;}

function rRoblox(r){
 if(r.found===false)return card("Roblox · "+r.query,"","<div class='none' style='padding:10px 0'>No Roblox account with that name or ID.</div>");
 const u=r.user||{};
 const info={"User ID":r.id,"Username":u.name,"Display name":u.displayName,"Created":(u.created||"").slice(0,10),
  "Banned":u.isBanned,"Verified badge":u.hasVerifiedBadge,"Bio":u.description,"Profile":`https://www.roblox.com/users/${r.id}/profile`};
 let h=(r.avatar?`<img class="av" src="${esc(r.avatar)}" alt="">`:"")+table(info);
 h+=`<h3>Social</h3>`+table({"Friends":r.counts?.friends,"Followers":r.counts?.followers,"Following":r.counts?.following});
 h+=`<h3>Previous usernames (${r.previous_usernames.length})</h3>`+(r.previous_usernames.length?`<div class="chips">${r.previous_usernames.map(n=>`<span class="chip">${esc(n)}</span>`).join("")}</div>`:`<div class="none">None</div>`);
 h+=`<h3>Groups (${r.groups.length})</h3>`+(r.groups.length?"<table>"+r.groups.map(g=>`<tr><td class="k"><a href="https://www.roblox.com/groups/${g.id}" target="_blank" rel="noopener">${esc(g.name)}</a></td><td>${esc(g.role)}</td></tr>`).join("")+"</table>":`<div class="none">None or hidden</div>`);
 h+=`<h3>Created games (${(r.games||[]).length})</h3>`+((r.games||[]).length?"<table>"+r.games.map(x=>`<tr><td class="k"><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.name)}</a></td><td>${(x.visits||0).toLocaleString()} visits</td></tr>`).join("")+"</table>":`<div class="none">None public</div>`);
 if(r.trading)h+=`<h3>Trading (Rolimons)</h3>`+table(r.trading);
 h+=`<h3>Recent badges</h3>`+(r.badges.length?`<div class="chips">${r.badges.map(b=>`<span class="chip">${esc(b)}</span>`).join("")}</div>`:`<div class="none">None visible</div>`);
 return card("Roblox · "+(u.name||r.query),"ID "+r.id,h);}

function rDomain(r){
 let h=`<h3>Registration</h3>`+table(r.rdap||{})+`<h3>DNS</h3>`+table(r.dns||{})+`<h3>Website</h3>`+table(r.web||{});
 h+=`<h3>Technology</h3>`+((r.technology||[]).length?`<div class="chips">${r.technology.map(t=>`<span class="chip">${esc(t)}</span>`).join("")}</div>`:`<div class="none">Nothing detected</div>`);
 h+=`<h3>Security headers</h3>`+table(r.security_headers||{});
 if((r.outbound_social_links||[]).length)h+=`<h3>Social links on the site</h3><div class="chips">${r.outbound_social_links.map(l=>`<a class="chip" href="https://${esc(l)}" target="_blank" rel="noopener">${esc(l)}</a>`).join("")}</div>`;
 h+=`<h3>History</h3>`+table(r.history||{});
 h+=`<h3>Subdomains from certificate logs (${r.subdomains.length})</h3>`+(r.subdomains.length?`<div class="chips">${r.subdomains.slice(0,150).map(s=>`<span class="chip">${esc(s)}</span>`).join("")}</div>`:`<div class="none">None found</div>`);
 return card("Domain · "+r.query,"",h);}
function rIp(r){const i=r.ipinfo||{};return card("IP · "+r.query,"",table({"Reverse DNS":r.rdns||i.hostname,"Organization / ASN":i.org,"Network":r.rdap_name,"City":i.city,"Region":i.region,"Country":i.country,"Coordinates":i.loc,"Timezone":i.timezone})+`<h3>Exposure (Shodan InternetDB)</h3>`+table({"Open ports":(r.shodan_internetdb||{}).ports,"Services":(r.shodan_internetdb||{}).cpes,"Tags":(r.shodan_internetdb||{}).tags,"Known CVEs":((r.shodan_internetdb||{}).vulns||[]).slice(0,20),"Hostnames":(r.shodan_internetdb||{}).hostnames})+`<h3>Spam / abuse blocklists</h3>`+table(r.blocklists||{})+`<div class="note">Location is approximate — usually the ISP, not a person.</div>`);}
function rEmail(r){let h=table({"Domain type":r.domain_type,"Mail servers (MX)":r.mx,"SPF":r.spf,"DMARC":r.dmarc});
 h+=`<h3>Gravatar public profile</h3>`+(r.gravatar?table(r.gravatar,["photos","hash","requestHash","thumbnailUrl","preferredUsername"]):`<div class="none">No public profile</div>`);
 return card("Email · "+r.query,"",h);}

function render(list){return list.map(r=>({user:rUser,username:rUser,roblox:rRoblox,domain:rDomain,ip:rIp,email:rEmail}[r.type]||(x=>card(r.type,"",table(x))))(r)).join("")
 +`<div class="row"><button class="ghost" onclick="dl()">Save as JSON</button><button class="ghost" onclick="copyAll()">Copy</button></div>`;}
function dl(){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(last,null,2)],{type:"application/json"}));a.download="lookup-"+Date.now()+".json";a.click();}
function copyAll(){navigator.clipboard.writeText(JSON.stringify(last,null,2));}

let hist=[],hasKey=false,isLocal=true,isCloud=false;
fetch("/api/status").then(r=>r.json()).then(s=>{isLocal=s.local;isCloud=s.cloud;hasKey=s.has_key;if(isLocal)$("#phbtn").style.display="block";});
async function openPhone(){const d=await fetch("/api/phone").then(r=>r.json());const m=$("#mbox");
 let h=`<h3>Use LOOKUP on your phone</h3>`;
 h+=`<div class="sw"><span>Phone access is <b>${d.enabled?"ON":"OFF"}</b></span><button style="background:${d.enabled?"transparent;color:var(--dim);border:1px solid var(--line2)":"var(--txt);color:#000"}" onclick="setPhone({enabled:${!d.enabled}})">${d.enabled?"Turn off":"Turn on"}</button></div>`;
 if(d.enabled){
  if(!d.links.length)h+=`<p class="note">Couldn't find this PC's network address.</p>`;
  for(const l of d.links)h+=`<h3 style="margin:16px 0 4px">${esc(l.label)}</h3>${l.qr?`<div class="qr">${l.qr}</div>`:""}<div class="lnk">${esc(l.url)}</div>`;
  h+=`<ol><li>Phone on the same Wi-Fi as this PC.</li><li>Scan the code with your camera and open the link.</li><li>Add it to your home screen (Share → Add to Home Screen) so it opens like an app.</li><li>If it won't load: Windows may have blocked it — allow Python on <b>Private networks</b> in the firewall prompt.</li></ol>
  <div class="row" style="justify-content:space-between"><button class="ghost" onclick="setPhone({reset:true})">New link (logs out other phones)</button><button class="ghost" onclick="$('#modal').classList.remove('on')">Done</button></div>`;
 }else h+=`<p class="note">When it's on, only devices that open your private link can use LOOKUP. Settings and your API key stay PC-only. Keep this PC on and LOOKUP open.</p>`;
 m.innerHTML=h;$("#modal").classList.add("on");}
async function setPhone(b){await fetch("/api/phone",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});openPhone();}
const SUGG=["Summarize what you found and what's worth checking next","Which results look like false positives?","Does this Roblox account look like an alt or a scam account?","Is this link/domain safe for my players?"];
function md(t){t=esc(t);t=t.replace(/^### ?(.*)$/gm,"<h4>$1</h4>").replace(/^## ?(.*)$/gm,"<h4>$1</h4>").replace(/\*\*(.+?)\*\*/g,"<b>$1</b>").replace(/`([^`]+)`/g,"<code>$1</code>")
 .replace(/(https?:\/\/[^\s<)]+)/g,'<a href="$1" target="_blank" rel="noopener">$1</a>');
 t=t.replace(/(?:^|\n)((?:[-*] .*(?:\n|$))+)/g,(m,b)=>"<ul>"+b.trim().split("\n").map(l=>"<li>"+l.slice(2)+"</li>").join("")+"</ul>");return t.replace(/\n/g,"<br>");}
function addMsg(role,html){const d=document.createElement("div");d.className="m "+(role=="user"?"u":"a");d.innerHTML=html;$("#msgs").appendChild(d);$("#msgs").scrollTop=1e9;return d;}
async function openChat(){document.body.classList.add("chat");const s=await fetch("/api/status").then(r=>r.json());hasKey=s.has_key;if(!hasKey)showKey();else if(!$("#msgs").children.length)welcome();$("#ci").focus();}
function welcome(){const d=addMsg("assistant",`I can read your results, explain them, and run more lookups to follow leads.<div class="sugg" style="margin-top:10px">${SUGG.map(s=>`<button type="button">${esc(s)}</button>`).join("")}</div>`);
 d.querySelectorAll(".sugg button").forEach(b=>b.onclick=()=>{$("#ci").value=b.textContent;send();});}
function newChat(){hist=[];$("#msgs").innerHTML="";hasKey?welcome():showKey();}
function showKey(){$("#msgs").innerHTML="";if(isCloud){addMsg("assistant","The AI needs an API key. In Render, open your LOOKUP service → <b>Environment</b>, add <b>ANTHROPIC_API_KEY</b> with your key, and save. It restarts by itself in about a minute.");return;}
 if(!isLocal){addMsg("assistant","The AI needs an API key, and that can only be set on your PC: open LOOKUP there, click <b>AI Analyst</b>, then <b>Key</b>.");return;}const d=addMsg("assistant",`<div class="keybox"><b>Connect an Anthropic API key</b><br><span style="color:var(--dim)">Get one at console.anthropic.com → API Keys. It's saved only on this PC, in your lookup folder.</span><input id="kk" type="password" placeholder="sk-ant-…"><button type="button" id="ks">Save key</button></div>`);
 d.querySelector("#ks").onclick=async()=>{const k=$("#kk").value.trim();if(!k)return;await fetch("/api/key",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({api_key:k})});hasKey=true;$("#msgs").innerHTML="";welcome();};}
async function send(){const t=$("#ci").value.trim();if(!t)return;if(!hasKey)return showKey();$("#ci").value="";
 addMsg("user",esc(t));hist.push({role:"user",content:t});const w=addMsg("assistant",'<div class="status" style="margin:0"><div class="spin"></div>Thinking…</div>');
 try{const r=await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({history:hist,context:last})}).then(r=>r.json());
  if(r.error=="nokey"){w.remove();return showKey();}if(r.error)throw new Error(r.error);
  w.innerHTML=md(r.reply||"")+(r.steps&&r.steps.length?`<div class="steps">Ran: ${r.steps.map(esc).join(" · ")}</div>`:"");
  hist.push({role:"assistant",content:r.reply||"(no reply)"});
  if(r.results&&r.results.length){last=(last||[]).concat(r.results);$("#out").innerHTML=`<div class="status">Analyst ran ${r.steps.length} lookup(s)</div>`+render(last);}
 }catch(e){w.innerHTML="Error: "+esc(e.message);hist.pop();}}
$("#cf").onsubmit=e=>{e.preventDefault();send();};
$("#ci").onkeydown=e=>{if(e.key=="Enter"&&!e.shiftKey){e.preventDefault();send();}};
$("#f").onsubmit=async e=>{e.preventDefault();const q=$("#q").value.trim();if(!q)return;
 $("#go").disabled=true;const t0=Date.now();
 $("#out").innerHTML=`<div class="status"><div class="spin"></div>Searching public sources…</div>`;
 try{const r=await fetch(`/api?type=${kind}&q=${encodeURIComponent(q)}`);const j=await r.json();
  if(j.error)throw new Error(j.error);last=j.results;
  $("#out").innerHTML=`<div class="status">Done in ${((Date.now()-t0)/1000).toFixed(1)}s</div>`+render(j.results);}
 catch(err){$("#out").innerHTML=`<div class="status">Error: ${esc(err.message)}</div>`;}
 $("#go").disabled=false;};
</script></body></html>"""


def enrich(results):
    """Add counts to Roblox results (the CLI prints them but doesn't return them)."""
    for r in results:
        if r.get("type") == "roblox" and r.get("id") and r.get("user"):
            uid = r["id"]
            base = f"https://friends.roblox.com/v1/users/{uid}"
            r["counts"] = {k: (lookup.get_json(f"{base}/{p}/count") or {}).get("count")
                           for k, p in (("friends", "friends"), ("followers", "followers"),
                                        ("following", "followings"))}
    return results


LOCAL = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

# Cloud mode (Render etc. set $PORT). Everyone must log in with LOOKUP_PASSWORD.
CLOUD = bool(os.environ.get("PORT") or os.environ.get("LOOKUP_CLOUD"))
PASSWORD = os.environ.get("LOOKUP_PASSWORD", "")
_fails = {}


def session_token():
    import hashlib
    import hmac
    return hmac.new(PASSWORD.encode(), b"lookup-session-v1", hashlib.sha256).hexdigest()


LOGIN = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#000">
<meta name="apple-mobile-web-app-capable" content="yes"><title>LOOKUP</title>
<style>body{margin:0;background:#000;color:#e8e8e8;font:15px system-ui,sans-serif;display:flex;
min-height:100vh;align-items:center;justify-content:center;padding:20px;box-sizing:border-box}
form{width:100%;max-width:340px;text-align:center}h1{letter-spacing:.5em;font-weight:600;font-size:20px}
input{width:100%;box-sizing:border-box;background:#0b0b0b;border:1px solid #2a2a2a;color:#e8e8e8;
padding:14px;border-radius:8px;font-size:16px;margin:18px 0 10px;outline:none}
button{width:100%;padding:14px;border:0;border-radius:8px;background:#e8e8e8;color:#000;font-weight:600;
font-size:15px}p{color:#888;font-size:13px;min-height:18px}</style></head><body>
<form method="post" action="/login"><h1>LOOKUP</h1>
<input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password">
<button>Enter</button><p>{msg}</p></form></body></html>"""


def lan_ips():
    """Addresses a phone could reach this PC on: Wi-Fi/LAN first, then Tailscale (100.64/10)."""
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    lan = [ip for ip in ips if ipaddress.ip_address(ip).is_private and
           not ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")]
    ts = [ip for ip in ips if ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")]
    return lan, ts


def phone_token():
    c = load_cfg()
    if not c.get("phone_token"):
        c["phone_token"] = secrets.token_urlsafe(12)
        save_cfg(c)
    return c["phone_token"]


def qr_svg(text):
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
        buf = io.BytesIO()
        img.save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype, headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def is_local(self):
        return not CLOUD and self.client_address[0] in LOCAL

    def cookie_token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "lk":
                return v
        return None

    def authorized(self):
        """Local requests always allowed. Other devices need phone access on + the secret link."""
        if CLOUD:
            ck = None
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "ls":
                    ck = v
            return bool(PASSWORD) and secrets.compare_digest(ck or "", session_token())
        if self.is_local():
            return True
        c = load_cfg()
        tok = c.get("phone_token")
        return bool(c.get("phone_enabled") and tok and
                    secrets.compare_digest(self.cookie_token() or "", tok))

    def deny(self):
        self.send(403, "<body style='background:#000;color:#aaa;font:15px system-ui;padding:40px'>"
                       "LOOKUP: this device isn't allowed. Open the phone link from the "
                       "<b>Phone</b> button on your PC.</body>", "text/html; charset=utf-8")

    def do_GET(self):
        u = urlparse(self.path)
        p = parse_qs(u.query)
        # Phone link: /?k=TOKEN -> set cookie, then redirect to a clean URL
        if u.path == "/" and "k" in p and not self.is_local():
            c = load_cfg()
            tok = c.get("phone_token") or ""
            if c.get("phone_enabled") and tok and secrets.compare_digest(p["k"][0], tok):
                return self.send(302, "", "text/plain", {
                    "Location": "/",
                    "Set-Cookie": f"lk={tok}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Strict"})
            return self.deny()
        if not self.authorized():
            if CLOUD:
                if u.path.startswith("/api"):
                    return self.send(401, json.dumps({"error": "Logged out — reload the page."}),
                                     "application/json")
                msg = "" if PASSWORD else "Set LOOKUP_PASSWORD in Render → Environment."
                return self.send(200, LOGIN.replace("{msg}", msg), "text/html; charset=utf-8")
            return self.deny()
        if u.path == "/":
            return self.send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/api":
            kind = (p.get("type") or ["auto"])[0]
            q = (p.get("q") or [""])[0].strip()[:200]
            if kind not in KINDS or not q:
                return self.send(400, json.dumps({"error": "bad request"}), "application/json")
            try:
                res = enrich(lookup.run(kind, q))
                for r in res:
                    r.pop("_ips", None)
                return self.send(200, json.dumps({"results": res}, default=str), "application/json")
            except Exception as e:
                return self.send(500, json.dumps({"error": str(e)}), "application/json")
        if u.path == "/api/status":
            c = load_cfg()
            return self.send(200, json.dumps({"has_key": bool(c.get("api_key") or
                                              os.environ.get("ANTHROPIC_API_KEY")),
                                              "model": c.get("model") or MODEL_DEFAULT,
                                              "local": self.is_local(), "cloud": CLOUD}),
                             "application/json")
        if u.path == "/api/phone":
            if not self.is_local():
                return self.send(403, "{}", "application/json")
            c = load_cfg()
            lan, ts = lan_ips()
            tok = phone_token()
            links = [{"label": "Same Wi-Fi", "url": f"http://{ip}:{PORT}/?k={tok}"} for ip in lan[:2]]
            links += [{"label": "Tailscale (anywhere)", "url": f"http://{ip}:{PORT}/?k={tok}"}
                      for ip in ts[:1]]
            for l in links:
                l["qr"] = qr_svg(l["url"])
            return self.send(200, json.dumps({"enabled": bool(c.get("phone_enabled")),
                                              "links": links}), "application/json")
        self.send(404, "not found", "text/plain")

    def do_POST(self):
        if CLOUD and self.path == "/login":
            ip = (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()
            n = int(self.headers.get("Content-Length") or 0)
            pw = (parse_qs(self.rfile.read(min(n, 4096)).decode("utf-8", "ignore")).get("password")
                  or [""])[0]
            if _fails.get(ip, 0) >= 8:
                time.sleep(3)
            if PASSWORD and secrets.compare_digest(pw.encode(), PASSWORD.encode()):
                _fails.pop(ip, None)
                return self.send(302, "", "text/plain", {
                    "Location": "/", "Set-Cookie": f"ls={session_token()}; Path=/; "
                    "Max-Age=31536000; HttpOnly; Secure; SameSite=Lax"})
            _fails[ip] = _fails.get(ip, 0) + 1
            time.sleep(1)
            return self.send(200, LOGIN.replace("{msg}", "Wrong password."), "text/html; charset=utf-8")
        origin = self.headers.get("Origin")
        ok_origins = {None, f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}",
                      f"http://{self.headers.get('Host')}", f"https://{self.headers.get('Host')}"}
        if origin not in ok_origins or not self.authorized():
            return self.send(403, "{}", "application/json")
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            body = {}
        # Settings are PC-only
        if self.path in ("/api/shutdown", "/api/key", "/api/phone") and (CLOUD or not self.is_local()):
            return self.send(403, "{}", "application/json")
        if self.path == "/api/shutdown":
            self.send(200, "{}", "application/json")
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        if self.path == "/api/key":
            c = load_cfg()
            if body.get("api_key") is not None:
                c["api_key"] = body["api_key"].strip()
            if body.get("model"):
                c["model"] = body["model"].strip()
            save_cfg(c)
            return self.send(200, "{}", "application/json")
        if self.path == "/api/phone":
            c = load_cfg()
            if "enabled" in body:
                c["phone_enabled"] = bool(body["enabled"])
            if body.get("reset"):
                c["phone_token"] = secrets.token_urlsafe(12)
            save_cfg(c)
            return self.send(200, "{}", "application/json")
        if self.path == "/api/chat":
            try:
                res = chat(body.get("history") or [], body.get("context"))
            except Exception as e:
                res = {"error": str(e)}
            return self.send(200, json.dumps(res, default=str), "application/json")
        self.send(404, "{}", "application/json")


def stop_old(url):
    try:
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(
            f"{url}/api/shutdown", data=b"{}", method="POST"), timeout=2)
        time.sleep(1.5)
    except Exception:
        pass


def main():
    if CLOUD:
        port = int(os.environ.get("PORT", "10000"))
        srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        print(f"LOOKUP cloud mode on :{port}" + ("" if PASSWORD else "  (WARNING: LOOKUP_PASSWORD not set)"),
              flush=True)
        srv.serve_forever()
        return
    url = f"http://127.0.0.1:{PORT}"
    stop_old(url)  # restart any copy that's already running so updates take effect
    srv = None
    for attempt in range(3):
        try:
            # 0.0.0.0 so a phone on the same network can connect; non-PC devices still need
            # phone access switched on AND the secret link (see Handler.authorized).
            srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
            break
        except OSError:
            time.sleep(1.5)
    if srv is None:
        print("  Another LOOKUP is already running and couldn't be restarted.\n"
              "  Close its window, then open LOOKUP again.")
        webbrowser.open(url)
        return
    print(f"\n  LOOKUP is running at {url}\n  Keep this window open. Close it to stop.\n")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
