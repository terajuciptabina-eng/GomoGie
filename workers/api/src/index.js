const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
});

const text = (value, max) => typeof value === "string" && value.trim().length > 0 && value.trim().length <= max;
const b64url = (bytes) => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};
const fromB64url = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(value => value.trim()).filter(Boolean);
  if (!origin || !allowed.includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "86400",
    "vary": "Origin"
  };
}

async function passwordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, key, 256);
  return "pbkdf2-sha256$100000$" + b64url(salt) + "$" + b64url(new Uint8Array(bits));
}

async function passwordVerify(password, stored) {
  try {
    const [scheme, rounds, saltText, hashText] = stored.split("$");
    if (scheme !== "pbkdf2-sha256" || Number(rounds) !== 100000) return false;
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64url(saltText), iterations: Number(rounds) }, key, 256);
    const actual = new Uint8Array(bits);
    const expected = fromB64url(hashText);
    if (actual.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch { return false; }
}

async function signToken(user, env, lifetimeSeconds = 2592000) {
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be configured with at least 32 characters");
  const header = b64url(encoder.encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const now = Math.floor(Date.now() / 1000);
  const subject = typeof user?.id === "string" ? user.id : user?.sub;
  if (typeof subject !== "string" || !subject) throw new Error("JWT subject is required");
  const payload = b64url(encoder.encode(JSON.stringify({ sub: subject, username: user.username || "", ver: Number(user.session_version || 0), iat: now, exp: now + lifetimeSeconds })));
  const input = header + "." + payload;
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(input));
  return input + "." + b64url(new Uint8Array(signature));
}

async function authenticate(request, env, diagnostic = null) {
  const reject = (reason) => { if (diagnostic) diagnostic.reason = reason; return null; };
  const value = request.headers.get("Authorization") || "";
  const match = value.match(/^Bearer\s+(.+)$/i);
  if (!match) return reject("missing_bearer");
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) return reject("jwt_secret_unavailable");
  try {
    const parts = match[1].split(".");
    if (parts.length !== 3 || parts.some(part => !part)) return reject("malformed_token");
    const [head, body, signature] = parts;
    const header = JSON.parse(decoder.decode(fromB64url(head)));
    if (header.alg !== "HS256" || header.typ !== "JWT") return reject("unsupported_token_header");
    const key = await crypto.subtle.importKey("raw", encoder.encode(env.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, fromB64url(signature), encoder.encode(head + "." + body));
    if (!valid) return reject("signature_invalid");
    const payload = JSON.parse(decoder.decode(fromB64url(body)));
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.sub !== "string" || !payload.sub || !Number.isInteger(payload.exp) ||
        !Number.isInteger(payload.iat) || payload.iat > now + 60 ||
        payload.exp - payload.iat > 2592000) return reject("invalid_claims");
    if (payload.exp <= now) return reject("token_expired");
    const account = await env.DB.prepare("SELECT status,session_version FROM users WHERE id = ?").bind(payload.sub).first();
    if (!account) return reject("account_not_found");
    if (account.status !== "active") return reject("account_inactive");
    if (Number(payload.ver || 0) !== Number(account.session_version || 0)) return reject("session_revoked");
    return payload;
  } catch { return reject("token_parse_or_verification_error"); }
}
async function readJson(request, maxBytes = 65536) {
  try {
    const declaredLength = Number(request.headers.get("content-length") || 0);
    if (declaredLength > maxBytes) return null;
    const raw = await request.text();
    if (encoder.encode(raw).byteLength > maxBytes) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

function uuid() { return crypto.randomUUID(); }

const IMAGE_LIMIT = 8 * 1024 * 1024;
function detectImageType(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  if (bytes.length >= 12 && String.fromCharCode(...bytes.slice(0,4)) === "RIFF" && String.fromCharCode(...bytes.slice(8,12)) === "WEBP") return "image/webp";
  if (bytes.length >= 6 && ["GIF87a","GIF89a"].includes(String.fromCharCode(...bytes.slice(0,6)))) return "image/gif";
  return null;
}
function mediaUrl(id) { return "https://gomogie-api.terajuciptabina.workers.dev/v1/media/" + encodeURIComponent(id); }
function videoUrl(id) { return "https://gomogie-api.terajuciptabina.workers.dev/v1/videos/" + encodeURIComponent(id); }
function isMp4(bytes) { return bytes.length >= 12 && String.fromCharCode(...bytes.slice(4,8)) === "ftyp"; }
const VIDEO_LIMIT = 50 * 1024 * 1024;



let newsSyncPromise = null;

const NEWS_FEEDS=[
{id:"bernama-en",name:"BERNAMA",url:"https://www.bernama.com/en/rssfeed.php/",language:"en",contentType:"article"},
{id:"thesun-my",name:"The Sun Malaysia",url:"https://thesun.my/feed/",language:"en",contentType:"article"},
{id:"astroawani-ms",name:"Astro AWANI",url:"https://www.astroawani.com/rss/latest/public",language:"ms",contentType:"article"},
{id:"mlstudios-articles",name:"ML Studios",url:"https://mlstudios.my/feed/",language:"ms",contentType:"article"},
{id:"mlstudios-video",name:"ML Studios",url:"https://www.youtube.com/feeds/videos.xml?channel_id=UCSkOqbajcG6-jguycOHzhDg",language:"ms",contentType:"video"},
{id:"aphd-video",name:"APHD Channel",url:"https://www.youtube.com/feeds/videos.xml?channel_id=UChpjlRq-Ikx8JRUiRauIAJg",language:"ms",contentType:"documentary"},
{id:"siakapkeli-articles",name:"Siakap Keli",url:"https://siakapkeli.my/feed",language:"ms",contentType:"article"},
{id:"siakapkeli-video",name:"Siakap Keli",url:"https://www.youtube.com/feeds/videos.xml?channel_id=UCo5TWROsmkTHVhzmFUW94oA",language:"ms",contentType:"video"},
{id:"google-my-ms",name:"Google News Malaysia",url:"https://news.google.com/rss?hl=ms&gl=MY&ceid=MY:ms",language:"ms",contentType:"article"},
{id:"google-my-en",name:"Google News Malaysia",url:"https://news.google.com/rss?hl=en-MY&gl=MY&ceid=MY:en",language:"en",contentType:"article"},
{id:"google-global",name:"Google News Global",url:"https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en",language:"en",contentType:"article"},
{id:"google-viral-ms",name:"Google News Trending",url:"https://news.google.com/rss/search?q=(viral+OR+trending+OR+popular+OR+populariti)+when:1d&hl=ms&gl=MY&ceid=MY:ms",language:"ms",contentType:"article"},
{id:"google-entertainment",name:"Google News Entertainment",url:"https://news.google.com/rss/search?q=(entertainment+OR+celebrity+OR+film+OR+music)+when:1d&hl=en-US&gl=US&ceid=US:en",language:"en",contentType:"article"},
{id:"google-tech",name:"Google News Technology",url:"https://news.google.com/rss/search?q=(technology+OR+AI+OR+gaming)+when:1d&hl=en-US&gl=US&ceid=US:en",language:"en",contentType:"article"},
{id:"google-sports",name:"Google News Sports",url:"https://news.google.com/rss/search?q=(sports+OR+football+OR+badminton)+when:1d&hl=en-US&gl=US&ceid=US:en",language:"en",contentType:"article"},
{id:"reddit-popular",name:"Reddit Popular",url:"https://www.reddit.com/r/popular/.rss",language:"en",contentType:"article"},
{id:"reddit-videos",name:"Reddit Videos",url:"https://www.reddit.com/r/videos/.rss",language:"en",contentType:"video"},
{id:"reddit-malaysia",name:"Reddit Malaysia",url:"https://www.reddit.com/r/malaysia/.rss",language:"en",contentType:"article"},
{id:"hackernews-top",name:"Hacker News",url:"https://news.ycombinator.com/rss",language:"en",contentType:"article"},
{id:"bbc-world",name:"BBC News World",url:"https://feeds.bbci.co.uk/news/world/rss.xml",language:"en",contentType:"article"},
{id:"bbc-top",name:"BBC News",url:"https://feeds.bbci.co.uk/news/rss.xml",language:"en",contentType:"article"},
{id:"bbc-tech",name:"BBC Technology",url:"https://feeds.bbci.co.uk/news/technology/rss.xml",language:"en",contentType:"article"},
{id:"bbc-sport",name:"BBC Sport",url:"https://feeds.bbci.co.uk/sport/rss.xml",language:"en",contentType:"article"},
{id:"guardian-world",name:"The Guardian World",url:"https://www.theguardian.com/world/rss",language:"en",contentType:"article"},
{id:"aljazeera-en",name:"Al Jazeera English",url:"https://www.aljazeera.com/xml/rss/all.xml",language:"en",contentType:"article"},
{id:"npr-news",name:"NPR News",url:"https://feeds.npr.org/1001/rss.xml",language:"en",contentType:"article"},
{id:"theverge-tech",name:"The Verge",url:"https://www.theverge.com/rss/index.xml",language:"en",contentType:"article"},
{id:"techcrunch",name:"TechCrunch",url:"https://techcrunch.com/feed/",language:"en",contentType:"article"},
{id:"wired-tech",name:"WIRED",url:"https://www.wired.com/feed/rss",language:"en",contentType:"article"},
{id:"sciencedaily",name:"ScienceDaily",url:"https://www.sciencedaily.com/rss/all.xml",language:"en",contentType:"article"},
{id:"ign-gaming",name:"IGN",url:"https://www.ign.com/rss/articles/feed",language:"en",contentType:"article"}
];
function decodeNewsXml(v){let s=String(v||"").replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,"$1");const entities=()=>s.replace(/&amp;/gi,"&").replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Number(n))).replace(/&#x([\da-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16)));s=entities();s=s.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi," ").replace(/<br\s*\/?\s*>|<\/(p|div|li|h[1-6])\s*>/gi," ").replace(/<[^>]*>/g," ");s=entities().replace(/<[^>]*>/g," ").replace(/\s+/g," ").trim();return s.replace(/Â/g,"").replace(/â€™/g,"'").replace(/â€œ|â€/g,'"').replace(/â€“|â€”/g,"-")}
function newsTag(block,name){const m=block.match(new RegExp("<"+name+"(?:\\s[^>]*)?>([\\s\\S]*?)</"+name+">","i"));return m?decodeNewsXml(m[1]):""}
function newsImageFromRss(block,articleUrl){
 const tags=[...block.matchAll(/<(media:thumbnail|media:content|enclosure|img)\b[^>]*>/gi)];
 for(const match of tags){
  const tag=match[0],raw=tag.match(/(?:url|src|data-src|data-original)\s*=\s*["']([^"']+)["']/i)?.[1]||"";
  if(!raw)continue;
  if(match[1].toLowerCase()==="enclosure"&&!/type\s*=\s*["']image\//i.test(tag))continue;
  if(match[1].toLowerCase()==="media:content"&&!/(?:type\s*=\s*["']image\/|medium\s*=\s*["']image)/i.test(tag))continue;
  try{const u=new URL(raw.replace(/&amp;/gi,"&"),articleUrl);if(["http:","https:"].includes(u.protocol)&&!/(logo|avatar|icon|sprite)/i.test(u.pathname))return u.href}catch{}
 }
 return "";
}
function newsCategory(title,summary){const v=(title+" "+summary).toLowerCase();if(/sport|football|soccer|badminton|tennis|sukan|bola sepak|olahraga/.test(v))return"sports";if(/business|econom|market|trade|finance|ringgit|bank|perniagaan|ekonomi|pasaran|kewangan|perdagangan/.test(v))return"business";if(/technology|digital|artificial intelligence|cyber|software|semiconductor|teknologi|kecerdasan buatan|siber/.test(v))return"technology";if(/politic|parliament|minister|election|government|cabinet|politik|menteri|parlimen|pilihan raya|kerajaan/.test(v))return"politics";if(/entertainment|celebrity|film|movie|cinema|music|singer|actor|actress|drama|television|tv show|concert|album|hiburan|selebriti|filem|wayang|muzik|penyanyi|pelakon|konsert|album|persembahan/.test(v))return"entertainment";if(/food|travel|culture|lifestyle|makanan|budaya|pelancongan|gaya hidup/.test(v))return"lifestyle";if(/world|global|international|asean|united states|china|europe|dunia|antarabangsa/.test(v))return"world";return"national"}
function newsRegion(title,summary){const v=(title+" "+summary).toLowerCase();const map=[["MY-PRK",/perak|ipoh|taiping|manjung|lumut|kuala kangsar|teluk intan|gerik/],["MY-KUL",/kuala lumpur|putrajaya/],["MY-SEL",/selangor|shah alam|petaling jaya|klang|subang jaya/],["MY-JHR",/johor|johor bahru|batu pahat|muar/],["MY-PNG",/penang|pulau pinang|george town/],["MY-KDH",/kedah|alor setar|sungai petani|langkawi/],["MY-NSN",/negeri sembilan|seremban/],["MY-MLK",/melaka|malacca/],["MY-PAH",/pahang|kuantan/],["MY-TRG",/terengganu|kuala terengganu/],["MY-KTN",/kelantan|kota bharu/],["MY-PLS",/perlis|kangar/],["MY-SBH",/sabah|kota kinabalu|tawau|sandakan/],["MY-SWK",/sarawak|kuching|miri|sibu/]];return map.find(x=>x[1].test(v))?.[0]||"MY"}
async function fetchNewsOgImage(articleUrl){
  try{
    const target=new URL(articleUrl);
    if(!["http:","https:"].includes(target.protocol))return "";
    const response=await fetch(target.href,{headers:{accept:"text/html,application/xhtml+xml;q=0.9","user-agent":"Mozilla/5.0 (compatible; GomoGieNews/1.1)"},signal:AbortSignal.timeout(7000)});
    if(!response.ok||!/html|xhtml/i.test(response.headers.get("content-type")||""))return "";
    const reader=response.body?.getReader();if(!reader)return "";
    const chunks=[];let total=0;
    while(total<250000){const part=await reader.read();if(part.done)break;const chunk=part.value.slice(0,250000-total);chunks.push(chunk);total+=chunk.length;if(chunk.length<part.value.length)break}
    try{await reader.cancel()}catch{}
    const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length}
    const source=new TextDecoder().decode(bytes);
    const parseAttrs=tag=>{const attrs={};for(const match of tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g))attrs[match[1].toLowerCase()]=match[2]??match[3]??match[4]??"";return attrs};
    const metaTags=source.match(/<meta\b[^>]*>/gi)||[];
    for(const key of ["og:image","og:image:secure_url","og:image:url","twitter:image","twitter:image:src"]){
      for(const tag of metaTags){const attrs=parseAttrs(tag);if((attrs.property||attrs.name||"").toLowerCase()===key&&attrs.content){const image=new URL(attrs.content.replace(/&amp;/gi,"&"),target);if(["http:","https:"].includes(image.protocol))return image.href}}
    }
    const imageTags=source.match(/<img\b[^>]*>/gi)||[];
    for(const tag of imageTags){const attrs=parseAttrs(tag),raw=attrs.src||attrs["data-src"]||attrs["data-original"]||attrs["data-lazy-src"]||"";if(!raw)continue;const candidate=new URL(raw.replace(/&amp;/gi,"&"),target);if(!["http:","https:"].includes(candidate.protocol))continue;const hint=(attrs.alt||"")+" "+(attrs.class||"")+" "+candidate.pathname;if(/logo|icon|avatar|banner|sprite/i.test(hint))continue;if(/storage\/photos|\/uploads\/|\/images\/|\.jpe?g(?:$|\?)|\.png(?:$|\?)|\.webp(?:$|\?)/i.test(hint))return candidate.href}
    const anchorTags=source.match(/<a\b[^>]*>/gi)||[];
    for(const tag of anchorTags){const attrs=parseAttrs(tag),raw=attrs.href||"";if(!raw)continue;const candidate=new URL(raw.replace(/&amp;/gi,"&"),target);if(!["http:","https:"].includes(candidate.protocol))continue;if(/\/storage\/photos\/.*(?:large|medium|small)?(?:\?|$)/i.test(candidate.pathname))return candidate.href}
  }catch{}
  return "";
}
async function fetchNewsArticleContent(articleUrl){
 try{
  const target=new URL(articleUrl);
  if(!["http:","https:"].includes(target.protocol))return null;
  const response=await fetch(target.href,{headers:{accept:"text/html,application/xhtml+xml;q=0.9","user-agent":"Mozilla/5.0 (compatible; GomoGieNews/1.1)"},signal:AbortSignal.timeout(8000)});
  if(!response.ok||!/html|xhtml/i.test(response.headers.get("content-type")||""))return null;
  const reader=response.body?.getReader();if(!reader)return null;
  const chunks=[];let total=0;
  while(total<500000){const part=await reader.read();if(part.done)break;const chunk=part.value.slice(0,500000-total);chunks.push(chunk);total+=chunk.length;if(chunk.length<part.value.length)break}
  try{await reader.cancel()}catch{}
  const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length}
  const source=new TextDecoder().decode(bytes);
  const meta=(key)=>{const tags=source.match(/<meta\b[^>]*>/gi)||[];for(const tag of tags){const name=tag.match(/(?:name|property)\s*=\s*["']([^"']+)["']/i)?.[1]?.toLowerCase(),content=tag.match(/content\s*=\s*["']([^"']*)["']/i)?.[1]||"";if(name===key.toLowerCase()&&content)return decodeNewsXml(content)}return""};
  const description=meta("og:description")||meta("description")||meta("twitter:description");
  const article=source.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i)?.[1]||source.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i)?.[1]||source;
  const clean=article.replace(/<(script|style|nav|footer|header|aside|form|noscript|svg)\b[^>]*>[\s\S]*?<\/\1>/gi," ").replace(/<(?:div|section|ul|ol|figure|figcaption|h[1-6])\b[^>]*>/gi," ").replace(/<\/(?:div|section|ul|ol|figure|figcaption|h[1-6])\s*>/gi," ");
  const paragraphs=[...clean.matchAll(/<p\b[^>]*>([\s\S]*?)<\/p>/gi)].map(m=>decodeNewsXml(m[1])).filter(p=>p.length>45&&!/^(share|read more|related|subscribe|advertisement|iklan|berita berkaitan|baca juga)\b/i.test(p));
  const unique=[...new Set(paragraphs)];
  let body=unique.join("\n\n").slice(0,6000);
  if(body.length<180){const text=decodeNewsXml(clean);if(text.length>body.length)body=text.slice(0,6000)}
  if(body.length<160)return description?{summary:description.slice(0,700),body:""}:null;
  return{summary:(description||body).slice(0,700),body};
 }catch{return null}
}
async function syncNewsFeedsSingleFlight(env) {
  if (newsSyncPromise) return newsSyncPromise;
  newsSyncPromise = syncNewsFeeds(env).finally(() => { newsSyncPromise = null; });
  return newsSyncPromise;
}

async function syncNewsFeeds(env){
 const now=new Date().toISOString();let inserted=0,checked=0,errors=0;
 // Read the active source list once per sync, instead of one D1 query per RSS source.
 const activeRows=await env.DB.prepare("SELECT id FROM gomogie_news_sources WHERE active=1").all();
 const activeSourceIds=new Set((activeRows.results||[]).map(row=>row.id));
 for(const feed of NEWS_FEEDS){
  if(!activeSourceIds.has(feed.id))continue;
  try{
   const res=await fetch(feed.url,{headers:{accept:"application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9","user-agent":"GomoGieContentDiscovery/1.0 (+https://terajuciptabina-eng.github.io/GomoGie/)"},signal:AbortSignal.timeout(12000)});
   if(!res.ok)throw new Error("Feed HTTP "+res.status);
   const xml=(await res.text()).slice(0,1500000),atom=/<feed\b/i.test(xml);
   const blocks=atom?[...xml.matchAll(/<entry\b[^>]*>([\s\S]*?)<\/entry>/gi)].map(x=>x[1]):[...xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)].map(x=>x[1]);
   for(const block of blocks.slice(0,40)){
    const title=newsTag(block,"title").slice(0,240),videoId=newsTag(block,"yt:videoId");
    const atomHref=block.match(/<link\b[^>]*rel=["']alternate["'][^>]*href=["']([^"']+)["'][^>]*\/?\s*>/i)?.[1]||block.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*\/?\s*>/i)?.[1]||"";
    const link=(newsTag(block,"link")||atomHref).replace(/&amp;/gi,"&").trim();
    const guid=newsTag(block,"guid")||newsTag(block,"id")||videoId,url=videoId?"https://www.youtube.com/watch?v="+encodeURIComponent(videoId):link;
    if(!title||!url||!/^https?:\/\//i.test(url))continue;
    const canonical=new URL(url);["utm_source","utm_medium","utm_campaign","utm_content","utm_term","fbclid","gclid"].forEach(k=>canonical.searchParams.delete(k));canonical.hash="";
    const raw=newsTag(block,"content:encoded")||newsTag(block,"media:description")||newsTag(block,"description")||newsTag(block,"summary")||"";
    const body=decodeNewsXml(raw).slice(0,6000),summary=body.slice(0,700);
    const image=newsImageFromRss(block,canonical.href)||block.match(/<media:thumbnail\b[^>]*url=["']([^"']+)["']/i)?.[1]||"";
    const dateRaw=newsTag(block,"pubDate")||newsTag(block,"published")||newsTag(block,"updated")||newsTag(block,"dc:date");
    const parsed=Date.parse(dateRaw),published=Number.isFinite(parsed)?new Date(parsed).toISOString():now;
    if(Date.now()-Date.parse(published)>(feed.contentType==="video"||feed.contentType==="documentary"?7:3)*24*3600000)continue;
    const kind=feed.contentType||"article",embed=videoId?"https://www.youtube-nocookie.com/embed/"+encodeURIComponent(videoId):"";
    const category=feed.id==="aphd-video"?"documentary":newsCategory(title,summary);
    const result=await env.DB.prepare("INSERT INTO gomogie_news_items (id,source_id,external_id,title,summary,body_text,image_url,canonical_url,category,region_code,published_at,fetched_at,status,content_type,embed_url) VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'published',?,?) ON CONFLICT(canonical_url) DO UPDATE SET summary=CASE WHEN length(excluded.summary)>length(gomogie_news_items.summary) THEN excluded.summary ELSE gomogie_news_items.summary END,body_text=CASE WHEN length(excluded.body_text)>length(COALESCE(gomogie_news_items.body_text,'')) THEN excluded.body_text ELSE gomogie_news_items.body_text END,image_url=COALESCE(NULLIF(excluded.image_url,''),gomogie_news_items.image_url),status='published',content_type=excluded.content_type,embed_url=COALESCE(NULLIF(excluded.embed_url,''),gomogie_news_items.embed_url),fetched_at=excluded.fetched_at").bind(uuid(),feed.id,guid||canonical.href,title,summary,body,image?new URL(image,canonical).href:"",canonical.href,category,newsRegion(title,summary),published,now,kind,embed).run();
    inserted+=Number(result.meta?.changes||0);checked++;
   }
   await env.DB.prepare("UPDATE gomogie_news_sources SET last_checked_at=?,last_error=NULL WHERE id=?").bind(now,feed.id).run();
  }catch(error){errors++;await env.DB.prepare("UPDATE gomogie_news_sources SET last_checked_at=?,last_error=? WHERE id=?").bind(now,String(error.message||error).slice(0,300),feed.id).run().catch(()=>{})}
 }
 await env.DB.prepare("UPDATE gomogie_news_items SET status='archived' WHERE status='published' AND content_type='article' AND julianday(published_at)<julianday('now','-72 hours')").run();
 await env.DB.prepare("DELETE FROM gomogie_news_items WHERE julianday(published_at)<julianday('now','-30 days')").run();
 return{inserted,checked,errors,at:now};
}

async function hydrateRecentNewsImages(env,limit=12){
 const rows=await env.DB.prepare("SELECT id,canonical_url FROM gomogie_news_items WHERE status='published' AND (image_url IS NULL OR image_url='') AND julianday(published_at)>=julianday('now','-72 hours') ORDER BY published_at DESC LIMIT ?").bind(limit).all();
 const items=rows.results||[];let updated=0;
 for(let i=0;i<items.length;i+=4){
  await Promise.all(items.slice(i,i+4).map(async item=>{
   const image=await fetchNewsOgImage(item.canonical_url);
   if(image){const result=await env.DB.prepare("UPDATE gomogie_news_items SET image_url=? WHERE id=? AND (image_url IS NULL OR image_url='')").bind(image,item.id).run();updated+=Number(result.meta?.changes||0)}
  }));
 }
 return{checked:items.length,updated};
}

async function route(request, env) {
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;

  if (path === "/v1/health" && method === "GET") {
    let database = "unavailable";
    let databaseReads = "unavailable";
    let mediaStorage = env.MEDIA_BUCKET ? "unavailable" : "not_configured";
    try {
      await env.DB.prepare("SELECT 1 AS ok").first();
      database = "available";
    } catch (error) {
      console.error("GomoGie health check: D1 connection unavailable", error);
    }
    try {
      await env.DB.prepare("SELECT id FROM users LIMIT 1").first();
      databaseReads = "available";
    } catch (error) {
      console.error("GomoGie health check: D1 read query unavailable", error);
    }
    if (env.MEDIA_BUCKET) {
      try {
        await env.MEDIA_BUCKET.list({ limit: 1 });
        mediaStorage = "available";
      } catch (error) {
        console.error("GomoGie health check: R2 unavailable", error);
      }
    }
    const connected = database === "available";
    const healthy = connected && databaseReads === "available" && mediaStorage === "available";
    return json({
      status: healthy ? "ok" : "degraded",
      checks: { database, databaseReads, mediaStorage },
      checkedAt: new Date().toISOString()
    }, connected ? 200 : 503);
  }

  if (path === "/v1/link-preview" && method === "GET") {
    const requested = url.searchParams.get("url") || "";
    const validateTarget = value => {
      let target; try { target = new URL(value); } catch { return null; }
      if (!["http:","https:"].includes(target.protocol) || target.username || target.password || (target.port && !["80","443"].includes(target.port))) return null;
      const host = target.hostname.toLowerCase().replace(/\.$/, "");
      if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".test") ||
          /^(127\.|10\.|192\.168\.|169\.254\.|0\.|22[4-9]\.|23[0-9]\.)/.test(host) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host) ||
          host === "::1" || host.startsWith("[fc") || host.startsWith("[fd") || host.startsWith("[fe80")) return null;
      target.hash = ""; return target;
    };
    let target = validateTarget(requested);
    if (!target) return json({ error: "invalid_url" }, 400);
    const cacheKey = new Request("https://gomogie-link-preview-cache-v2.invalid/" + encodeURIComponent(target.href));
    const cached = await caches.default.match(cacheKey);
    if (cached) return new Response(cached.body, { status: cached.status, headers: cached.headers });
    let response = null;
    for (let hop = 0; hop < 4; hop++) {
      try { response = await fetch(target.href, { redirect: "manual", headers: { accept: "text/html,application/xhtml+xml;q=0.9", "user-agent": "GomoGieLinkPreview/1.0" }, signal: AbortSignal.timeout(5000) }); }
      catch { return json({ error: "preview_unavailable" }, 502); }
      if ([301,302,303,307,308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location || hop === 3) return json({ error: "too_many_redirects" }, 502);
        target = validateTarget(new URL(location, target).href);
        if (!target) return json({ error: "invalid_redirect" }, 400);
        continue;
      }
      break;
    }
    const type = response?.headers.get("content-type") || "";
    if (!response?.ok || !/text\/(html|xhtml)/i.test(type)) return json({ error: "not_html" }, 415);
    const reader = response.body?.getReader();
    if (!reader) return json({ error: "empty_response" }, 502);
    const chunks = []; let total = 0;
    while (true) { const part = await reader.read(); if (part.done) break; total += part.value.byteLength; if (total > 524288) { await reader.cancel(); return json({ error: "page_too_large" }, 413); } chunks.push(part.value); }
    const bytes = new Uint8Array(total); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const source = decoder.decode(bytes);
    const decode = value => String(value || "").replace(/&amp;/gi,"&").replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Number(n))).replace(/&#x([\da-f]+);/gi,(_,n)=>String.fromCodePoint(parseInt(n,16))).trim();
    const getMeta = key => {
      const tags = source.match(/<meta\b[^>]*>/gi) || [];
      for (const tag of tags) {
        const name = tag.match(/\b(?:property|name)\s*=\s*["']([^"']+)["']/i)?.[1];
        const content = tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i)?.[1];
        if (name?.toLowerCase() === key.toLowerCase() && content) return decode(content).slice(0,2000);
      }
      return "";
    };
    const title = getMeta("og:title") || getMeta("twitter:title") || decode(source.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || "");
    const description = getMeta("og:description") || getMeta("description") || getMeta("twitter:description");
    let image = getMeta("og:image") || getMeta("twitter:image");
    if (image) { try { image = new URL(image, target).href; if (!/^https?:\/\//i.test(image)) image = ""; } catch { image = ""; } }
    const result = { url: target.href, hostname: target.hostname, title: title.slice(0,180), description: description.slice(0,300), image };
    const output = json(result, 200, { "cache-control": "public, max-age=3600" });
    await caches.default.put(cacheKey, output.clone());
    return output;
  }

  if (path === "/health/live" && method === "GET") {
    return json({ status: "ok", service: "gomogie-api", runtime: "cloudflare-workers" });
  }
  if (path === "/v1/news/status" && method === "GET") {
    try {
      const [sources, counts, bySource] = await Promise.all([
        env.DB.prepare("SELECT id,name,active,last_checked_at,last_error FROM gomogie_news_sources ORDER BY name,id").all(),
        env.DB.prepare("SELECT status,content_type,COUNT(*) AS total FROM gomogie_news_items GROUP BY status,content_type").all(),
        env.DB.prepare("SELECT s.id,s.name,COUNT(CASE WHEN n.status='published' THEN 1 END) AS published_count,MAX(n.published_at) AS latest_published_at,(SELECT title FROM gomogie_news_items x WHERE x.source_id=s.id AND x.status='published' ORDER BY x.published_at DESC LIMIT 1) AS latest_title FROM gomogie_news_sources s LEFT JOIN gomogie_news_items n ON n.source_id=s.id GROUP BY s.id,s.name ORDER BY published_count DESC,s.name").all()
      ]);
      const sourceState = new Map((bySource.results || []).map(row => [row.id, row]));
      return json({
        checkedAt: new Date().toISOString(),
        schedule: "*/15 * * * *",
        sources: (sources.results || []).map(row => {
          const stats = sourceState.get(row.id) || {};
          return { id: row.id, name: row.name, active: Boolean(row.active), lastCheckedAt: row.last_checked_at, lastError: row.last_error, publishedCount: Number(stats.published_count || 0), latestPublishedAt: stats.latest_published_at || null, latestTitle: stats.latest_title || null };
        }),
        counts: counts.results || []
      });
    } catch (error) {
      return json({ error: "news_status_unavailable", message: String(error.message || error).slice(0, 240) }, 503);
    }
  }

  if (path === "/health/ready" && method === "GET") {
    try {
      await env.DB.prepare("SELECT 1 AS ready").first();
      return json({ status: "ready", database: "connected" });
    } catch {
      return json({ status: "not_ready", database: "unavailable" }, 503);
    }
  }

  if (path === "/v1/auth/register" && method === "POST") {
    if (env.ALLOW_REGISTRATION !== "true") {
      return json({ error: "registration_closed", message: "Pendaftaran awam belum dibuka." }, 403);
    }
    const input = await readJson(request);
    if (!input || !text(input.email, 254) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email.trim()) ||
        !text(input.username, 24) || !/^[a-zA-Z0-9_]{3,24}$/.test(input.username.trim()) ||
        typeof input.password !== "string" || input.password.length < 9 || input.password.length > 128 ||
        !text(input.displayName, 60)) {
      return json({ error: "validation_error", message: "Email, username, kata laluan (9–128 aksara) dan nama paparan diperlukan." }, 400);
    }
    const email = input.email.trim().toLowerCase();
    const username = input.username.trim().toLowerCase();
    const exists = await env.DB.prepare("SELECT id FROM users WHERE email = ? OR username = ?").bind(email, username).first();
    if (exists) return json({ error: "account_exists", message: "Email atau username telah digunakan." }, 409);

    const id = uuid();
    const now = new Date().toISOString();
    const hash = await passwordHash(input.password);
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users (id,email,username,password_hash,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)")
          .bind(id, email, username, hash, "active", now, now),
        env.DB.prepare("INSERT INTO profiles (user_id,display_name,bio,created_at,updated_at) VALUES (?,?,?,?,?)")
          .bind(id, input.displayName.trim(), "", now, now)
      ]);
    } catch (error) {
      return json({ error: "registration_failed", message: "Pendaftaran gagal. Semak email dan username." }, 409);
    }
    const user = { id, email, username };
    return json({ user, profile: { user_id: id, display_name: input.displayName.trim(), bio: "" }, accessToken: await signToken(user, env, 2592000), tokenType: "Bearer", expiresIn: 2592000 }, 201);
  }

  if (path === "/v1/auth/login" && method === "POST") {
    const input = await readJson(request);
    if (!input || !text(input.login, 254) || typeof input.password !== "string" || input.password.length > 128) {
      return json({ error: "validation_error" }, 400);
    }
    const user = await env.DB.prepare("SELECT id,email,username,password_hash,status,session_version FROM users WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE")
      .bind(input.login.trim(), input.login.trim()).first();
    if (!user || user.status === "deleted" || !(await passwordVerify(input.password, user.password_hash))) {
      return json({ error: "invalid_credentials", message: "Maklumat log masuk tidak tepat." }, 401);
    }
    let accountRestored = false;
    if (user.status === "deactivated" || user.status === "pending_deletion") {
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET status='active',updated_at=? WHERE id=?").bind(new Date().toISOString(), user.id),
        env.DB.prepare("UPDATE gomogie_account_deletion_requests SET status='cancelled' WHERE user_id=? AND status='pending'").bind(user.id)
      ]);
      accountRestored = true;
    } else if (user.status !== "active") {
      return json({ error: "account_unavailable", message: "Akaun ini tidak tersedia." }, 403);
    }
    return json({ user: { id: user.id, email: user.email, username: user.username }, accessToken: await signToken(user, env, 2592000), tokenType: "Bearer", expiresIn: 2592000, accountRestored });
  }

  const publicCommentsRead = method === "GET" && /^\/v1\/posts\/[0-9a-f-]+\/comments$/i.test(path);
  const publicMediaRead = method === "GET" && /^\/v1\/media\/[0-9a-f-]+$/i.test(path);
  const publicVideoRead = method === "GET" && /^\/v1\/videos\/[0-9a-f-]+$/i.test(path);
  const followingFeedRequest = path === "/v1/feed" && url.searchParams.get("scope") === "following";
  const optionalFeedAuth = path === "/v1/feed" && !!request.headers.get("Authorization");
  const optionalNewsAuth = path === "/v1/news" && !!request.headers.get("Authorization");
  const newsPreferencesRequest = path === "/v1/news/preferences";
  const communityRequest = path === "/v1/communities" || path.startsWith("/v1/communities/");
  const publicRelationshipRead = method === "GET" && /^\/v1\/users\/[a-zA-Z0-9_]{3,24}\/(relationships|followers|following)$/.test(path);
  const needsAuth = !publicRelationshipRead && (communityRequest || newsPreferencesRequest || followingFeedRequest || optionalFeedAuth || optionalNewsAuth || path === "/v1/auth/me" || (path === "/v1/auth/remember" && method === "POST") || ((path.startsWith("/v1/posts") && !publicCommentsRead) || path.startsWith("/v1/saved")) || (path.startsWith("/v1/media") && !publicMediaRead) || (path.startsWith("/v1/videos") && !publicVideoRead) || path.startsWith("/v1/users/") || path.startsWith("/v1/account/") || path.startsWith("/v1/notifications") || (path.startsWith("/v1/push/") && !(path === "/v1/push/public-key" && method === "GET")) || path.startsWith("/v1/conversations") || path === "/v1/friends" || path === "/v1/friend-requests" || path.startsWith("/v1/friend-requests/") || path === "/v1/message-requests");
  const authDiagnostic = {};
  const auth = needsAuth ? await authenticate(request, env, authDiagnostic) : null;
  if (needsAuth && !auth) return json({ error: "unauthorized", code: authDiagnostic.reason || "authentication_failed", message: "Sesi tidak dapat disahkan." }, 401);

  if (path === "/v1/account/username" && method === "PUT") {
    const input = await readJson(request), username = typeof input?.username === "string" ? input.username.trim() : "";
    if (!/^[a-zA-Z0-9_]{3,24}$/.test(username) || typeof input?.password !== "string") return json({ error: "validation_error", message: "Username mesti 3–24 aksara, menggunakan huruf, nombor atau underscore." }, 400);
    const account = await env.DB.prepare("SELECT password_hash,session_version FROM users WHERE id=? AND status='active'").bind(auth.sub).first();
    if (!account || !(await passwordVerify(input.password, account.password_hash))) return json({ error: "password_incorrect", message: "Kata laluan semasa tidak tepat." }, 403);
    const duplicate = await env.DB.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE AND id<>?").bind(username, auth.sub).first();
    if (duplicate) return json({ error: "username_taken", message: "Username ini sudah digunakan." }, 409);
    await env.DB.prepare("UPDATE users SET username=?,updated_at=? WHERE id=?").bind(username, new Date().toISOString(), auth.sub).run();
    const user = { id: auth.sub, username, session_version: account.session_version };
    return json({ user, accessToken: await signToken(user, env, 2592000) });
  }

  if (path === "/v1/account/password" && method === "PUT") {
    const input = await readJson(request);
    if (!input || typeof input.currentPassword !== "string" || typeof input.newPassword !== "string" || input.newPassword.length < 9 || input.newPassword.length > 128) return json({ error: "validation_error", message: "Kata laluan baharu mesti 9–128 aksara." }, 400);
    const account = await env.DB.prepare("SELECT password_hash FROM users WHERE id=? AND status='active'").bind(auth.sub).first();
    if (!account || !(await passwordVerify(input.currentPassword, account.password_hash))) return json({ error: "password_incorrect", message: "Kata laluan semasa tidak tepat." }, 403);
    await env.DB.prepare("UPDATE users SET password_hash=?,session_version=session_version+1,updated_at=? WHERE id=?").bind(await passwordHash(input.newPassword), new Date().toISOString(), auth.sub).run();
    const updated = await env.DB.prepare("SELECT id,username,session_version FROM users WHERE id=?").bind(auth.sub).first();
    return json({ updated: true, accessToken: await signToken(updated, env, 2592000) });
  }

  if (path === "/v1/account/logout-all" && method === "POST") {
    const input = await readJson(request);
    if (typeof input?.password !== "string") return json({ error: "validation_error", message: "Masukkan kata laluan untuk mengesahkan tindakan." }, 400);
    const account = await env.DB.prepare("SELECT password_hash FROM users WHERE id=? AND status='active'").bind(auth.sub).first();
    if (!account || !(await passwordVerify(input.password, account.password_hash))) return json({ error: "password_incorrect", message: "Kata laluan semasa tidak tepat." }, 403);
    await env.DB.prepare("UPDATE users SET session_version=session_version+1,updated_at=? WHERE id=?").bind(new Date().toISOString(),auth.sub).run();
    const updated = await env.DB.prepare("SELECT id,username,session_version FROM users WHERE id=?").bind(auth.sub).first();
    return json({ revokedOtherSessions: true, accessToken: await signToken(updated,env,2592000) });
  }

  if (path === "/v1/account/deactivate" && method === "POST") {
    const input = await readJson(request);
    if (typeof input?.password !== "string") return json({ error: "validation_error", message: "Masukkan kata laluan untuk mengesahkan tindakan." }, 400);
    const account = await env.DB.prepare("SELECT password_hash FROM users WHERE id=? AND status='active'").bind(auth.sub).first();
    if (!account || !(await passwordVerify(input.password, account.password_hash))) return json({ error: "password_incorrect", message: "Kata laluan semasa tidak tepat." }, 403);
    await env.DB.prepare("UPDATE users SET status='deactivated',session_version=session_version+1,updated_at=? WHERE id=?").bind(new Date().toISOString(), auth.sub).run();
    return json({ deactivated: true, message: "Akaun dinyahaktifkan. Log masuk semula untuk mengaktifkannya." });
  }

  if (path === "/v1/account/delete" && method === "POST") {
    const input = await readJson(request);
    if (input?.confirmation !== "DELETE" || typeof input.password !== "string") return json({ error: "confirmation_required", message: "Taip DELETE dan masukkan kata laluan untuk meneruskan." }, 400);
    const account = await env.DB.prepare("SELECT password_hash FROM users WHERE id=? AND status='active'").bind(auth.sub).first();
    if (!account || !(await passwordVerify(input.password, account.password_hash))) return json({ error: "password_incorrect", message: "Kata laluan semasa tidak tepat." }, 403);
    const now = new Date(), scheduled = new Date(now.getTime() + 30 * 86400000);
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET status='pending_deletion',session_version=session_version+1,updated_at=? WHERE id=?").bind(now.toISOString(), auth.sub),
      env.DB.prepare("INSERT INTO gomogie_account_deletion_requests (user_id,requested_at,scheduled_for,status) VALUES (?,?,?,'pending') ON CONFLICT(user_id) DO UPDATE SET requested_at=excluded.requested_at,scheduled_for=excluded.scheduled_for,status='pending'").bind(auth.sub, now.toISOString(), scheduled.toISOString())
    ]);
    return json({ deletionScheduled: true, scheduledFor: scheduled.toISOString(), recoveryDays: 30, message: "Permintaan pemadaman dijadualkan selepas 30 hari. Log masuk semula dalam tempoh ini untuk membatalkannya." });
  }

  if (path === "/v1/auth/me" && method === "GET") {
    const user = await env.DB.prepare("SELECT id,email,username FROM users WHERE id=? AND status='active'").bind(auth.sub).first();
    if (!user) return json({ error: "unauthorized", message: "Akaun tidak aktif." }, 401);
    const profile = await env.DB.prepare("SELECT display_name,bio,avatar_url,cover_url,website,location,is_private FROM profiles WHERE user_id=?").bind(auth.sub).first();
    return json({
      user,
      profile: {
        displayName: profile?.display_name || user.username,
        bio: profile?.bio || "",
        avatarUrl: profile?.avatar_url || "",
        coverUrl: profile?.cover_url || "",
        website: profile?.website || "",
        location: profile?.location || "",
        isPrivate: Boolean(profile?.is_private)
      }
    });
  }

  if (path === "/v1/auth/remember" && method === "POST") {
    return json({ accessToken: await signToken(auth, env, 2592000), tokenType: "Bearer", expiresIn: 2592000 });
  }


  // Communities: all membership and content access is enforced server-side.
  if (path === "/v1/communities" && method === "GET") {
    const q = (url.searchParams.get("q") || "").trim().slice(0,80);
    const rows = await env.DB.prepare(
      "SELECT c.id,c.owner_id,c.name,c.slug,c.description,c.visibility,c.created_at," +
      "(SELECT COUNT(*) FROM community_members cm WHERE cm.community_id=c.id AND cm.status='active') member_count," +
      "(SELECT status FROM community_members mine WHERE mine.community_id=c.id AND mine.user_id=?) my_status," +
      "(SELECT membership_role FROM community_members mine WHERE mine.community_id=c.id AND mine.user_id=?) my_role," +
      "u.username owner_username,p.display_name owner_name,p.avatar_url owner_avatar " +
      "FROM communities c JOIN users u ON u.id=c.owner_id LEFT JOIN profiles p ON p.user_id=u.id " +
      "WHERE (c.visibility='public' OR c.owner_id=? OR EXISTS(SELECT 1 FROM community_members mine WHERE mine.community_id=c.id AND mine.user_id=? AND mine.status='active')) " +
      "AND (?='' OR c.name LIKE '%'||?||'%' OR c.description LIKE '%'||?||'%') ORDER BY member_count DESC,c.created_at DESC LIMIT 100"
    ).bind(auth.sub,auth.sub,auth.sub,auth.sub,q,q,q).all();
    return json({items:(rows.results||[]).map(c=>({id:c.id,name:c.name,slug:c.slug,description:c.description,visibility:c.visibility,createdAt:c.created_at,memberCount:Number(c.member_count||0),membershipStatus:c.my_status||null,membershipRole:c.my_role||null,owner:{id:c.owner_id,username:c.owner_username,displayName:c.owner_name||c.owner_username,avatarUrl:c.owner_avatar||""}}))});
  }
  if (path === "/v1/communities" && method === "POST") {
    const input=await readJson(request);
    const name=String(input?.name||"").trim(),description=String(input?.description||"").trim(),visibility=input?.visibility||"public";
    if(!text(name,60)||description.length>500||!["public","private","approval"].includes(visibility))return json({error:"validation_error",message:"Nama komuniti diperlukan (maksimum 60 aksara); penerangan maksimum 500 aksara."},400);
    const slugBase=name.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,48)||"community";
    const slug=slugBase+"-"+uuid().slice(0,8),id=uuid(),now=new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO communities (id,owner_id,name,slug,description,visibility,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)").bind(id,auth.sub,name,slug,description,visibility,now,now),
      env.DB.prepare("INSERT INTO community_members (community_id,user_id,membership_role,status,joined_at) VALUES (?,?, 'owner','active',?)").bind(id,auth.sub,now)
    ]);
    return json({community:{id,name,slug,description,visibility,createdAt:now,memberCount:1,membershipStatus:"active",membershipRole:"owner"}},201);
  }
  const communityPath=path.match(/^\/v1\/communities\/([a-z0-9-]+)(?:\/(join|leave|members|posts|rules|events|reports)(?:\/([0-9a-f-]+))?)?$/i);
  if(communityPath){
    const slug=communityPath[1],action=communityPath[2]||"";
    const community=await env.DB.prepare("SELECT * FROM communities WHERE slug=?").bind(slug).first();
    if(!community)return json({error:"community_not_found"},404);
    const mine=await env.DB.prepare("SELECT membership_role,status FROM community_members WHERE community_id=? AND user_id=?").bind(community.id,auth.sub).first();
    const isMember=mine?.status==="active",isManager=isMember&&["owner","moderator"].includes(mine.membership_role);
    if(action!=="join"&&community.visibility!=="public"&&community.owner_id!==auth.sub&&!isMember)return json({error:"community_not_found"},404);
    if(action==="join"&&method==="POST"){
      if(isMember)return json({membershipStatus:"active",membershipRole:mine.membership_role});
      const status=community.visibility==="approval"||community.visibility==="private"?"pending":"active",now=new Date().toISOString();
      await env.DB.prepare("INSERT INTO community_members (community_id,user_id,membership_role,status,joined_at) VALUES (?,?,'member',?,?) ON CONFLICT(community_id,user_id) DO UPDATE SET status=excluded.status,joined_at=excluded.joined_at").bind(community.id,auth.sub,status,now).run();
      return json({membershipStatus:status},201);
    }
    if(action==="leave"&&method==="POST"){
      if(community.owner_id===auth.sub)return json({error:"owner_cannot_leave",message:"Pemilik perlu memindahkan pemilikan atau memadam komuniti."},409);
      await env.DB.prepare("DELETE FROM community_members WHERE community_id=? AND user_id=?").bind(community.id,auth.sub).run();
      return json({left:true});
    }
    const memberAction=path.match(/^\/v1\/communities\/([a-z0-9-]+)\/members\/([0-9a-f-]+)$/i);
    if(memberAction&&method==="PATCH"){
      if(!isManager)return json({error:"forbidden"},403);
      const targetId=memberAction[2],input=await readJson(request);
      if(targetId===community.owner_id)return json({error:"owner_role_locked"},409);
      const target=await env.DB.prepare("SELECT membership_role,status FROM community_members WHERE community_id=? AND user_id=?").bind(community.id,targetId).first();
      if(!target)return json({error:"member_not_found"},404);
      if(input?.status==="active"||input?.status==="banned"||input?.status==="pending"){
        await env.DB.prepare("UPDATE community_members SET status=? WHERE community_id=? AND user_id=?").bind(input.status,community.id,targetId).run();
      }else if(["moderator","member"].includes(input?.role)&&community.owner_id===auth.sub){
        await env.DB.prepare("UPDATE community_members SET membership_role=? WHERE community_id=? AND user_id=?").bind(input.role,community.id,targetId).run();
      }else return json({error:"validation_error"},400);
      return json({updated:true});
    }
    if(action==="rules"&&method==="GET"){
      const rows=await env.DB.prepare("SELECT id,title,body,position FROM community_rules WHERE community_id=? ORDER BY position,id").bind(community.id).all();
      return json({items:rows.results||[]});
    }
    if(action==="rules"&&method==="POST"){
      if(!isManager)return json({error:"forbidden"},403);
      const input=await readJson(request);if(!text(input?.title,100)||!text(input?.body,1000))return json({error:"validation_error"},400);
      const id=uuid();await env.DB.prepare("INSERT INTO community_rules (id,community_id,title,body,position,created_at) VALUES (?,?,?,?,?,?)").bind(id,community.id,input.title.trim(),input.body.trim(),Number(input.position)||0,new Date().toISOString()).run();
      return json({rule:{id,title:input.title.trim(),body:input.body.trim()}},201);
    }
    if(action==="events"&&method==="GET"){
      const rows=await env.DB.prepare("SELECT id,title,description,starts_at,location,creator_id FROM community_events WHERE community_id=? AND starts_at>=? ORDER BY starts_at LIMIT 50").bind(community.id,new Date().toISOString()).all();
      return json({items:rows.results||[]});
    }
    if(action==="events"&&method==="POST"){
      if(!isMember)return json({error:"membership_required"},403);
      const input=await readJson(request),start=Date.parse(input?.startsAt);
      if(!text(input?.title,100)||!Number.isFinite(start)||start<Date.now()||String(input?.description||"").length>1000||String(input?.location||"").length>160)return json({error:"validation_error",message:"Tajuk, tarikh masa hadapan dan butiran acara yang sah diperlukan."},400);
      const id=uuid();await env.DB.prepare("INSERT INTO community_events (id,community_id,creator_id,title,description,starts_at,location,created_at) VALUES (?,?,?,?,?,?,?,?)").bind(id,community.id,auth.sub,input.title.trim(),String(input.description||"").trim(),new Date(start).toISOString(),String(input.location||"").trim(),new Date().toISOString()).run();
      return json({event:{id,title:input.title.trim(),starts_at:new Date(start).toISOString()}},201);
    }
    if(action==="reports"&&method==="POST"){
      const input=await readJson(request);
      if(!["community","post","member"].includes(input?.targetType)||!text(input?.targetId,80)||!text(input?.reason,500))return json({error:"validation_error"},400);
      const duplicate=await env.DB.prepare("SELECT id FROM community_reports WHERE community_id=? AND reporter_id=? AND target_type=? AND target_id=? AND status='open'").bind(community.id,auth.sub,input.targetType,input.targetId).first();
      if(duplicate)return json({reported:true,duplicate:true});
      const id=uuid();await env.DB.prepare("INSERT INTO community_reports (id,community_id,reporter_id,target_type,target_id,reason,status,created_at) VALUES (?,?,?,?,?,?,'open',?)").bind(id,community.id,auth.sub,input.targetType,input.targetId,input.reason.trim(),new Date().toISOString()).run();
      return json({reported:true},201);
    }
    const reportAction=path.match(/^\/v1\/communities\/([a-z0-9-]+)\/reports\/([0-9a-f-]+)$/i);
    if(reportAction&&method==="PATCH"){
      if(!isManager)return json({error:"forbidden"},403);
      const input=await readJson(request);
      if(!["reviewed","dismissed","actioned"].includes(input?.status))return json({error:"validation_error"},400);
      const result=await env.DB.prepare("UPDATE community_reports SET status=?,reviewed_by=?,reviewed_at=? WHERE id=? AND community_id=?").bind(input.status,auth.sub,new Date().toISOString(),reportAction[2],community.id).run();
      if(!result.meta?.changes)return json({error:"report_not_found"},404);
      return json({updated:true});
    }
    if(action==="reports"&&method==="GET"){
      if(!isManager)return json({error:"forbidden"},403);
      const rows=await env.DB.prepare("SELECT id,reporter_id,target_type,target_id,reason,status,created_at FROM community_reports WHERE community_id=? ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END,created_at DESC LIMIT 100").bind(community.id).all();
      return json({items:rows.results||[]});
    }
    if(action==="members"&&method==="GET"){
      if(community.visibility!=="public"&&!isMember&&community.owner_id!==auth.sub)return json({error:"forbidden"},403);
      const rows=await env.DB.prepare("SELECT cm.user_id,cm.membership_role,cm.status,cm.joined_at,u.username,p.display_name,p.avatar_url FROM community_members cm JOIN users u ON u.id=cm.user_id LEFT JOIN profiles p ON p.user_id=u.id WHERE cm.community_id=? AND (cm.status='active' OR ?=1) ORDER BY CASE cm.membership_role WHEN 'owner' THEN 0 WHEN 'moderator' THEN 1 ELSE 2 END,cm.joined_at LIMIT 200").bind(community.id,isManager?1:0).all();
      return json({items:(rows.results||[]).map(m=>({userId:m.user_id,username:m.username,displayName:m.display_name||m.username,avatarUrl:m.avatar_url||"",role:m.membership_role,status:m.status,joinedAt:m.joined_at}))});
    }
    if(action==="posts"&&method==="GET"){
      if(!isMember&&community.visibility!=="public")return json({error:"forbidden"},403);
      const rows=await env.DB.prepare("SELECT p.id,p.user_id,p.content,p.visibility,p.created_at,u.username,pr.display_name,pr.avatar_url FROM community_posts cp JOIN posts p ON p.id=cp.post_id JOIN users u ON u.id=p.user_id LEFT JOIN profiles pr ON pr.user_id=u.id WHERE cp.community_id=? AND p.status='published' ORDER BY p.created_at DESC LIMIT 50").bind(community.id).all();
      return json({items:(rows.results||[]).map(p=>({id:p.id,content:p.content,createdAt:p.created_at,author:{id:p.user_id,username:p.username,displayName:p.display_name||p.username,avatarUrl:p.avatar_url||""}}))});
    }
    if(action==="posts"&&method==="POST"){
      if(!isMember)return json({error:"membership_required",message:"Sertai komuniti dahulu untuk membuat hantaran."},403);
      const input=await readJson(request);if(!text(input?.content,5000))return json({error:"validation_error",message:"Hantaran diperlukan (maksimum 5,000 aksara)."},400);
      const id=uuid(),now=new Date().toISOString();
      await env.DB.batch([
        env.DB.prepare("INSERT INTO posts (id,user_id,content,visibility,status,comments_enabled,created_at,updated_at) VALUES (?,?,?,'public','published',1,?,?)").bind(id,auth.sub,input.content.trim(),now,now),
        env.DB.prepare("INSERT INTO community_posts (community_id,post_id,created_at) VALUES (?,?,?)").bind(community.id,id,now)
      ]);
      return json({post:{id,content:input.content.trim(),createdAt:now}},201);
    }
    if(!action&&method==="PATCH"){
      if(community.owner_id!==auth.sub)return json({error:"forbidden"},403);
      const input=await readJson(request),name=String(input?.name||"").trim(),description=String(input?.description||"").trim(),visibility=input?.visibility||community.visibility;
      if(!text(name,60)||description.length>500||!["public","private","approval"].includes(visibility))return json({error:"validation_error"},400);
      await env.DB.prepare("UPDATE communities SET name=?,description=?,visibility=?,updated_at=? WHERE id=?").bind(name,description,visibility,new Date().toISOString(),community.id).run();
      return json({updated:true});
    }
    if(!action&&method==="DELETE"){
      if(community.owner_id!==auth.sub)return json({error:"forbidden"},403);
      await env.DB.batch([
        env.DB.prepare("DELETE FROM community_posts WHERE community_id=?").bind(community.id),
        env.DB.prepare("DELETE FROM community_members WHERE community_id=?").bind(community.id),
        env.DB.prepare("DELETE FROM communities WHERE id=?").bind(community.id)
      ]);
      return json({deleted:true});
    }
    if(!action&&method==="GET"){
      const count=await env.DB.prepare("SELECT COUNT(*) n FROM community_members WHERE community_id=? AND status='active'").bind(community.id).first();
      const owner=await env.DB.prepare("SELECT u.id,u.username,p.display_name,p.avatar_url FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.id=?").bind(community.owner_id).first();
      return json({community:{id:community.id,name:community.name,slug:community.slug,description:community.description,visibility:community.visibility,createdAt:community.created_at,memberCount:Number(count?.n||0),membershipStatus:mine?.status||null,membershipRole:mine?.membership_role||null,owner:{id:owner.id,username:owner.username,displayName:owner.display_name||owner.username,avatarUrl:owner.avatar_url||""}}});
    }
  }

  const mediaReadMatch = path.match(/^\/v1\/media\/([0-9a-f-]+)$/i);
  if (mediaReadMatch && method === "GET") {
    if (!env.MEDIA_BUCKET) return json({ error: "media_storage_unavailable" }, 503);
    const asset = await env.DB.prepare("SELECT object_key,mime_type,size_bytes FROM gomogie_media_assets WHERE id=? AND status='ready'").bind(mediaReadMatch[1]).first();
    if (!asset) return json({ error: "media_not_found" }, 404);
    const object = await env.MEDIA_BUCKET.get(asset.object_key);
    if (!object) return json({ error: "media_not_found" }, 404);
    return new Response(object.body, { headers: { "content-type": asset.mime_type, "content-length": String(asset.size_bytes), "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff" } });
  }

  const videoReadMatch = path.match(/^\/v1\/videos\/([0-9a-f-]+)$/i);
  if (videoReadMatch && method === "GET") {
    if (!env.MEDIA_BUCKET) return json({ error: "media_storage_unavailable" }, 503);
    const asset = await env.DB.prepare("SELECT object_key,size_bytes FROM gomogie_video_assets WHERE id=? AND status='ready'").bind(videoReadMatch[1]).first();
    if (!asset) return json({ error: "video_not_found" }, 404);
    const rangeHeader=request.headers.get("Range");
    let object,headers={"content-type":"video/mp4","accept-ranges":"bytes","cache-control":"public, max-age=31536000, immutable","x-content-type-options":"nosniff"};
    if(rangeHeader){
      const match=rangeHeader.match(/^bytes=(\d*)-(\d*)$/);
      if(!match)return new Response(null,{status:416,headers:{"content-range":"bytes */"+asset.size_bytes,"accept-ranges":"bytes"}});
      let start=match[1]?Number(match[1]):null,end=match[2]?Number(match[2]):null;
      if(start===null){const suffix=end||0;start=Math.max(0,asset.size_bytes-suffix);end=asset.size_bytes-1}
      else if(end===null)end=asset.size_bytes-1;
      if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||start<0||end<start||start>=asset.size_bytes)return new Response(null,{status:416,headers:{"content-range":"bytes */"+asset.size_bytes,"accept-ranges":"bytes"}});
      end=Math.min(end,asset.size_bytes-1);
      object=await env.MEDIA_BUCKET.get(asset.object_key,{range:{offset:start,length:end-start+1}});
      if(!object)return json({error:"video_not_found"},404);
      headers["content-length"]=String(end-start+1);headers["content-range"]="bytes "+start+"-"+end+"/"+asset.size_bytes;
      return new Response(object.body,{status:206,headers});
    }
    object=await env.MEDIA_BUCKET.get(asset.object_key);
    if(!object)return json({error:"video_not_found"},404);
    headers["content-length"]=String(asset.size_bytes);
    return new Response(object.body,{headers});
  }

  if (path === "/v1/videos" && method === "POST") {
    const declaredLength = Number(request.headers.get("content-length") || 0);
    if (declaredLength > VIDEO_LIMIT + 65536) return json({ error: "file_size_invalid", message: "Saiz video maksimum ialah 50 MB." }, 413);
    if (!env.MEDIA_BUCKET) return json({ error: "media_storage_unavailable", message: "Cloudflare R2 belum dihubungkan kepada Worker." }, 503);
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return json({ error: "validation_error", message: "Fail video diperlukan." }, 400);
    if (!file.size || file.size > VIDEO_LIMIT) return json({ error: "file_size_invalid", message: "Saiz video maksimum ialah 50 MB." }, 413);
    if (file.type !== "video/mp4") return json({ error: "unsupported_video", message: "Format video yang disokong ialah MP4." }, 415);
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (!isMp4(bytes)) return json({ error: "unsupported_video", message: "Fail bukan MP4 yang sah." }, 415);
    const id = uuid(), now = new Date().toISOString(), key = "users/" + auth.sub + "/videos/" + id + ".mp4";
    await env.MEDIA_BUCKET.put(key, bytes, { httpMetadata: { contentType: "video/mp4", cacheControl: "public, max-age=31536000, immutable" }, customMetadata: { ownerId: auth.sub, purpose: "video" } });
    try {
      await env.DB.prepare("INSERT INTO gomogie_video_assets (id,owner_id,object_key,mime_type,size_bytes,status,created_at) VALUES (?,?,?,?,?,?,?)").bind(id, auth.sub, key, "video/mp4", file.size, "ready", now).run();
    } catch (error) { await env.MEDIA_BUCKET.delete(key); throw error; }
    return json({ video: { id, url: videoUrl(id), mimeType: "video/mp4", size: file.size, createdAt: now } }, 201);
  }

  if (path === "/v1/message-files" && method === "POST") {
    const limit=20*1024*1024,declared=Number(request.headers.get("content-length")||0);
    if(declared>limit+65536)return json({error:"file_size_invalid",message:"Saiz fail maksimum ialah 20 MB."},413);
    if(!env.MEDIA_BUCKET)return json({error:"media_storage_unavailable",message:"Cloudflare R2 belum tersedia."},503);
    const form=await request.formData(),file=form.get("file");
    const allowed=new Set(["application/pdf","text/plain","application/zip","application/vnd.openxmlformats-officedocument.wordprocessingml.document","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","application/msword","application/vnd.ms-excel"]);
    if(!(file instanceof File)||!file.size||file.size>limit||!allowed.has(file.type))return json({error:"unsupported_file",message:"Fail yang disokong: PDF, DOC/DOCX, XLS/XLSX, TXT dan ZIP sehingga 20 MB."},415);
    const id=uuid(),now=new Date().toISOString(),name=String(file.name||"attachment").replace(/[^a-zA-Z0-9._ -]/g,"_").slice(0,120)||"attachment",key="users/"+auth.sub+"/messages/"+id;
    await env.MEDIA_BUCKET.put(key,new Uint8Array(await file.arrayBuffer()),{httpMetadata:{contentType:file.type,cacheControl:"private, no-store"},customMetadata:{ownerId:auth.sub,fileName:name}});
    try{await env.DB.prepare("INSERT INTO gomogie_message_files (id,owner_id,object_key,file_name,mime_type,size_bytes,created_at) VALUES (?,?,?,?,?,?,?)").bind(id,auth.sub,key,name,file.type,file.size,now).run()}
    catch(error){await env.MEDIA_BUCKET.delete(key);throw error}
    return json({file:{id,name,mimeType:file.type,size:file.size,url:"/v1/message-files/"+id}},201);
  }
  const messageFileRead=path.match(/^\/v1\/message-files\/([0-9a-f-]+)$/i);
  if(messageFileRead&&method==="GET"){
    const asset=await env.DB.prepare("SELECT object_key,file_name,mime_type,size_bytes FROM gomogie_message_files WHERE id=?").bind(messageFileRead[1]).first();
    if(!asset||!env.MEDIA_BUCKET)return json({error:"file_not_found"},404);
    const object=await env.MEDIA_BUCKET.get(asset.object_key);if(!object)return json({error:"file_not_found"},404);
    const disposition=url.searchParams.get("download")==="1"?"attachment":"inline";
    return new Response(object.body,{headers:{"content-type":asset.mime_type,"content-length":String(asset.size_bytes),"content-disposition":disposition+'; filename="'+asset.file_name.replace(/["\\\\]/g,"_")+'"',"cache-control":"private, no-store","x-content-type-options":"nosniff"}});
  }
  if (path === "/v1/media" && method === "POST") {
    const declaredLength = Number(request.headers.get("content-length") || 0);
    if (declaredLength > IMAGE_LIMIT + 65536) return json({ error: "file_size_invalid", message: "Saiz gambar maksimum ialah 8 MB." }, 413);
    if (!env.MEDIA_BUCKET) return json({ error: "media_storage_unavailable", message: "Cloudflare R2 belum dihubungkan kepada Worker." }, 503);
    const form = await request.formData();
    const file = form.get("file"), purpose = form.get("purpose");
    if (!(file instanceof File) || !["avatar","cover","post","message"].includes(purpose)) return json({ error: "validation_error", message: "Fail gambar dan tujuan upload diperlukan." }, 400);
    if (!file.size || file.size > IMAGE_LIMIT) return json({ error: "file_size_invalid", message: "Saiz gambar maksimum ialah 8 MB." }, 413);
    const bytes = new Uint8Array(await file.arrayBuffer());
    const detected = detectImageType(bytes);
    if (!detected || detected !== file.type) return json({ error: "unsupported_image", message: "Format yang disokong: JPEG, PNG, WebP dan GIF." }, 415);
    const id = uuid(), now = new Date().toISOString();
    const extension = ({ "image/jpeg":"jpg", "image/png":"png", "image/webp":"webp", "image/gif":"gif" })[detected];
    const key = "users/" + auth.sub + "/" + purpose + "/" + id + "." + extension;
    await env.MEDIA_BUCKET.put(key, bytes, { httpMetadata: { contentType: detected, cacheControl: "public, max-age=31536000, immutable" }, customMetadata: { ownerId: auth.sub, purpose } });
    try {
      const statements = [env.DB.prepare("INSERT INTO gomogie_media_assets (id,owner_id,purpose,object_key,mime_type,size_bytes,status,created_at) VALUES (?,?,?,?,?,?,?,?)").bind(id, auth.sub, purpose, key, detected, file.size, "ready", now)];
      if (purpose === "avatar" || purpose === "cover") {
        const column = purpose === "avatar" ? "avatar_url" : "cover_url";
        statements.push(env.DB.prepare("UPDATE profiles SET " + column + "=?,updated_at=? WHERE user_id=?").bind(mediaUrl(id), now, auth.sub));
      }
      await env.DB.batch(statements);
    } catch (error) { await env.MEDIA_BUCKET.delete(key); throw error; }
    return json({ media: { id, purpose, url: mediaUrl(id), mimeType: detected, size: file.size, createdAt: now } }, 201);
  }

  if (path === "/v1/auth/me" && method === "GET") {
    const row = await env.DB.prepare("SELECT u.id,u.email,u.username,u.status,u.created_at,p.display_name,p.bio,p.avatar_url,p.cover_url,p.website,p.location,p.is_private FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.id=?")
      .bind(auth.sub).first();
    if (!row || row.status !== "active") return json({ error: "user_not_found" }, 404);
    return json({ user: { id: row.id, email: row.email, username: row.username, createdAt: row.created_at }, profile: { displayName: row.display_name, bio: row.bio, avatarUrl: row.avatar_url, coverUrl: row.cover_url, website: row.website, location: row.location, isPrivate: Boolean(row.is_private) } });
  }

  if (path === "/v1/auth/me" && method === "PUT") {
    const input = await readJson(request);
    if (!input || !text(input.displayName, 60) ||
        (input.bio !== undefined && typeof input.bio !== "string") ||
        (input.location !== undefined && typeof input.location !== "string") ||
        (input.website !== undefined && typeof input.website !== "string") ||
        (input.avatarUrl !== undefined && typeof input.avatarUrl !== "string") ||
        (input.coverUrl !== undefined && typeof input.coverUrl !== "string") || (input.isPrivate !== undefined && typeof input.isPrivate !== "boolean")) {
      return json({ error: "validation_error", message: "Maklumat profil tidak sah." }, 400);
    }
    const fields = {
      bio: (input.bio || "").trim(),
      location: (input.location || "").trim(),
      website: (input.website || "").trim(),
      avatarUrl: (input.avatarUrl || "").trim(),
      coverUrl: (input.coverUrl || "").trim()
    };
    if (fields.bio.length > 160 || fields.location.length > 80 || fields.website.length > 120 ||
        fields.avatarUrl.length > 2048 || fields.coverUrl.length > 2048) {
      return json({ error: "validation_error", message: "Satu atau lebih medan melebihi had aksara." }, 400);
    }
    for (const value of [fields.website, fields.avatarUrl, fields.coverUrl]) {
      if (value && !/^https:\/\//i.test(value)) {
        return json({ error: "invalid_url", message: "Pautan profil mestilah bermula dengan https://." }, 400);
      }
    }
    const now = new Date().toISOString();
    await env.DB.prepare(
      "UPDATE profiles SET display_name=?,bio=?,location=?,website=?,avatar_url=COALESCE(?,avatar_url),cover_url=COALESCE(?,cover_url),is_private=COALESCE(?,is_private),updated_at=? WHERE user_id=?"
    ).bind(input.displayName.trim(), fields.bio, fields.location, fields.website,
      fields.avatarUrl || null, fields.coverUrl || null, input.isPrivate === undefined ? null : (input.isPrivate ? 1 : 0), now, auth.sub).run();
    const row = await env.DB.prepare(
      "SELECT u.id,u.email,u.username,u.created_at,p.display_name,p.bio,p.avatar_url,p.cover_url,p.website,p.location,p.is_private FROM users u JOIN profiles p ON p.user_id=u.id WHERE u.id=?"
    ).bind(auth.sub).first();
    if (!row) return json({ error: "profile_not_found" }, 404);
    return json({ user: { id: row.id, email: row.email, username: row.username, createdAt: row.created_at },
      profile: { displayName: row.display_name, bio: row.bio, avatarUrl: row.avatar_url,
        coverUrl: row.cover_url, website: row.website, location: row.location, isPrivate: Boolean(row.is_private) } });
  }

  if(path==="/v1/push/public-key"&&method==="GET")return json({publicKey:env.VAPID_PUBLIC_KEY||null,configured:!!(env.VAPID_PUBLIC_KEY&&env.VAPID_PRIVATE_JWK&&env.VAPID_SUBJECT)});
  if(path==="/v1/push/subscribe"&&method==="POST"){
    const input=await readJson(request),sub=input?.subscription;
    if(!sub?.endpoint||!sub?.keys?.p256dh||!sub?.keys?.auth)return json({error:"invalid_subscription"},400);
    let endpoint;try{endpoint=new URL(sub.endpoint);if(endpoint.protocol!=="https:")throw new Error()}catch{return json({error:"invalid_endpoint"},400)}
    const now=new Date().toISOString(),id=uuid();
    await env.DB.prepare("INSERT INTO gomogie_push_subscriptions (id,user_id,endpoint,p256dh,auth_secret,created_at,updated_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,p256dh=excluded.p256dh,auth_secret=excluded.auth_secret,updated_at=excluded.updated_at")
      .bind(id,auth.sub,endpoint.href,sub.keys.p256dh,sub.keys.auth,now,now).run();
    return json({subscribed:true});
  }
  if(path==="/v1/push/subscribe"&&method==="DELETE"){
    const input=await readJson(request),endpoint=typeof input?.endpoint==="string"?input.endpoint:"";
    if(!endpoint)return json({error:"endpoint_required"},400);
    await env.DB.prepare("DELETE FROM gomogie_push_subscriptions WHERE user_id=? AND endpoint=?").bind(auth.sub,endpoint).run();
    return json({subscribed:false});
  }
  if (path === "/v1/notifications" && method === "GET") {
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 30)));
    const rows = await env.DB.prepare(
      "SELECT n.id,n.type,n.entity_id,n.is_read,n.created_at,n.actor_id,u.username,p.display_name,p.avatar_url FROM notifications n LEFT JOIN users u ON u.id=n.actor_id LEFT JOIN profiles p ON p.user_id=n.actor_id WHERE n.recipient_id=? ORDER BY n.created_at DESC LIMIT ?"
    ).bind(auth.sub, limit).all();
    const unread = await env.DB.prepare("SELECT COUNT(*) AS count FROM notifications WHERE recipient_id=? AND is_read=0").bind(auth.sub).first();
    return json({ items: (rows.results || []).map(row => ({ id: row.id, type: row.type, entityId: row.entity_id, isRead: Boolean(row.is_read), createdAt: row.created_at, actor: row.actor_id ? { id: row.actor_id, username: row.username, displayName: row.display_name, avatarUrl: row.avatar_url } : null })), unreadCount: Number(unread?.count || 0) });
  }
  const notificationReadMatch = path.match(/^\/v1\/notifications\/([0-9a-f-]+)\/read$/i);
  if (notificationReadMatch && method === "PATCH") {
    const result = await env.DB.prepare("UPDATE notifications SET is_read=1 WHERE id=? AND recipient_id=?").bind(notificationReadMatch[1], auth.sub).run();
    if (!result.meta?.changes) return json({ error: "notification_not_found" }, 404);
    return json({ updated: true });
  }
  if (path === "/v1/notifications/read-all" && method === "PATCH") {
    const result = await env.DB.prepare("UPDATE notifications SET is_read=1 WHERE recipient_id=? AND is_read=0").bind(auth.sub).run();
    return json({ updated: Number(result.meta?.changes || 0) });
  }

  if(path==="/v1/news/preferences"&&method==="GET"){const row=await env.DB.prepare("SELECT region_code,interests_json FROM gomogie_news_preferences WHERE user_id=?").bind(auth.sub).first();let interests=["national","politics","business","technology","sports","entertainment","world","lifestyle"];try{if(row?.interests_json)interests=JSON.parse(row.interests_json)}catch{}return json({region:row?.region_code||"MY",interests})}
  if(path==="/v1/news/preferences"&&method==="PUT"){const input=await readJson(request),regions=["MY","MY-PRK","MY-KUL","MY-SEL","MY-JHR","MY-PNG","MY-KDH","MY-NSN","MY-MLK","MY-PAH","MY-TRG","MY-KTN","MY-PLS","MY-SBH","MY-SWK"],categories=["national","politics","business","technology","sports","entertainment","world","lifestyle"],interests=Array.isArray(input?.interests)?[...new Set(input.interests.filter(x=>categories.includes(x)))]:null;if(!input||!regions.includes(input.region)||!interests||!interests.length)return json({error:"validation_error",message:"Pilih lokasi dan sekurang-kurangnya satu minat."},400);await env.DB.prepare("INSERT INTO gomogie_news_preferences (user_id,region_code,interests_json,updated_at) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET region_code=excluded.region_code,interests_json=excluded.interests_json,updated_at=excluded.updated_at").bind(auth.sub,input.region,JSON.stringify(interests),new Date().toISOString()).run();return json({saved:true,region:input.region,interests})}
  if(path==="/v1/news"&&method==="GET"){
    const requestedMode=url.searchParams.get("mode");const mode=["global","archive","videos"].includes(requestedMode)?requestedMode:"for-you";
    const limit=Math.min(mode==="videos"?100:30,Math.max(1,Number(url.searchParams.get("limit")||(mode==="videos"?60:12))));
    let region="MY",interests=["national","politics","business","technology","sports","entertainment","world","lifestyle"];
    if(auth&&mode==="for-you"){
      const pref=await env.DB.prepare("SELECT region_code,interests_json FROM gomogie_news_preferences WHERE user_id=?").bind(auth.sub).first();
      region=pref?.region_code||"MY";
      try{if(pref?.interests_json)interests=JSON.parse(pref.interests_json)}catch{}
    }
    const archiveMode=mode==="archive";if(!archiveMode)await env.DB.prepare("UPDATE gomogie_news_items SET status='archived' WHERE status='published' AND julianday(published_at)<julianday('now','-72 hours')").run();const base="WITH ranked_news AS (SELECT n.id,n.title,n.summary,n.body_text,n.image_url,n.canonical_url,n.category,n.region_code,n.published_at,n.content_type,n.embed_url,n.source_id,s.name AS source_name,s.language AS language,(SELECT COUNT(*) FROM gomogie_news_items t WHERE t.category=n.category AND julianday(t.published_at)>=julianday('now','-12 hours')) AS trend_score,ROW_NUMBER() OVER (PARTITION BY n.source_id ORDER BY n.published_at DESC) AS source_rank FROM gomogie_news_items n JOIN gomogie_news_sources s ON s.id=n.source_id WHERE n.status='"+(archiveMode?"archived":"published")+"' AND julianday(n.published_at)>=julianday('now','-"+(archiveMode?"30":mode==="videos"?"7":"3")+" days') ) SELECT * FROM ranked_news WHERE source_rank<=100 ";
    const readItems=async()=>{
      if(mode==="videos"){
        return await env.DB.prepare(base+"AND content_type IN ('video','documentary') ORDER BY published_at DESC LIMIT ?").bind(limit).all();
      }
      if(mode==="for-you"&&auth){
        const regionClause=region==="MY"?"":" AND region_code IN ('MY',?)";
        const sql=base+"AND category IN (SELECT value FROM json_each(?))"+regionClause+" ORDER BY CASE WHEN region_code=? THEN 0 ELSE 1 END,published_at DESC LIMIT ?";
        const binds=region==="MY"?[JSON.stringify(interests),region,limit]:[JSON.stringify(interests),region,region,limit];
        return await env.DB.prepare(sql).bind(...binds).all();
      }
      return await env.DB.prepare(base+"ORDER BY published_at DESC LIMIT ?").bind(limit).all();
    };
    let rows=await readItems();
    let refreshed=false;
    // Only the primary For You request may trigger an on-demand feed sync.
    // The frontend requests several modes in parallel; letting each empty mode sync
    // independently multiplies D1 reads and writes during an empty catalogue.
    if(mode==="for-you"&&!(rows.results||[]).length){
      const last=await env.DB.prepare("SELECT last_checked_at FROM gomogie_news_sources WHERE id='bernama-en' AND active=1").first();
      const lastAt=last?.last_checked_at?Date.parse(last.last_checked_at):0;
      if(!lastAt||Date.now()-lastAt>120000){
        refreshed=true;
        await syncNewsFeedsSingleFlight(env);
        rows=await readItems();
      }
    }
    const currentItems=(rows.results||[]);
    // Article and image hydration is deliberately limited to For You. Global,
    // Archive and Videos are read-only discovery queries and must not fan out
    // into dozens of extra publisher fetches and D1 updates.
    if(mode==="for-you"){
      const missingImages=currentItems.filter(item=>!item.image_url&&item.canonical_url).slice(0,6);
      const needArticle=currentItems.filter(item=>(item.content_type||"article")==="article"&&item.canonical_url&&(!item.body_text||String(item.body_text).trim().length<180||String(item.body_text).trim()===String(item.summary||"").trim())).slice(0,4);
      await Promise.all([
        ...missingImages.map(async item=>{const image=await fetchNewsOgImage(item.canonical_url);if(image){item.image_url=image;await env.DB.prepare("UPDATE gomogie_news_items SET image_url=? WHERE id=? AND (image_url IS NULL OR image_url='')").bind(image,item.id).run()}}),
        ...needArticle.map(async item=>{const article=await fetchNewsArticleContent(item.canonical_url);if(article){if(article.body)item.body_text=article.body;if(!item.summary||String(item.summary).trim()===String(item.body_text||"").trim())item.summary=article.summary||String(article.body||"").slice(0,700);await env.DB.prepare("UPDATE gomogie_news_items SET summary=CASE WHEN ?<>'' THEN ? ELSE summary END,body_text=CASE WHEN ?<>'' THEN ? ELSE body_text END WHERE id=?").bind(article.summary||"",article.summary||"",article.body||"",article.body||"",item.id).run()}})
      ]);
    }
    const source=await env.DB.prepare("SELECT name,last_checked_at,last_error FROM gomogie_news_sources WHERE id='bernama-en'").first();
    return json({mode,region,interests,refreshed,sourceStatus:{name:source?.name||"BERNAMA",lastCheckedAt:source?.last_checked_at||null,lastError:source?.last_error||null},items:(rows.results||[]).map(x=>({...x,title:decodeNewsXml(x.title).replace(/Â/g,""),summary:(x.content_type==="video"||x.content_type==="documentary")?"":decodeNewsXml(x.summary).replace(/Â/g,""),body_text:(x.content_type==="video"||x.content_type==="documentary")?"":decodeNewsXml(x.body_text).replace(/Â/g,""),trendScore:Number(x.trend_score||0)}))});
  }
  if (path === "/v1/feed" && method === "GET") {
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 20)));
    const select = "SELECT p.id,p.user_id,p.content,p.visibility,p.created_at,p.comments_enabled,u.username,pr.display_name,pr.avatar_url,pr.cover_url," +
      "(SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) AS reaction_count," +
      "(SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id AND c.status='published') AS comment_count,ma.id AS media_id,va.id AS video_id,gp.id AS poll_id,gp.closes_at AS poll_closes_at " +
      "FROM posts p JOIN users u ON u.id=p.user_id LEFT JOIN profiles pr ON pr.user_id=p.user_id " +
      "LEFT JOIN gomogie_post_media pm ON pm.post_id=p.id LEFT JOIN gomogie_media_assets ma ON ma.id=pm.media_id AND ma.status='ready' " +
      "LEFT JOIN gomogie_post_videos pv ON pv.post_id=p.id LEFT JOIN gomogie_video_assets va ON va.id=pv.video_id AND va.status='ready' " +
      "LEFT JOIN gomogie_polls gp ON gp.post_id=p.id ";
    const rows = followingFeedRequest
      ? await env.DB.prepare(select +
          "WHERE p.status='published' AND (p.user_id=? OR EXISTS (" +
          "SELECT 1 FROM follows f WHERE f.follower_id=? AND f.following_id=p.user_id AND f.status='accepted' " +
          "AND p.visibility IN ('public','followers'))) ORDER BY p.created_at DESC LIMIT ?"
        ).bind(auth.sub, auth.sub, limit).all()
      : await env.DB.prepare(select +
          "WHERE p.status='published' AND p.visibility='public' ORDER BY p.created_at DESC LIMIT ?"
        ).bind(limit).all();
    const items = await Promise.all((rows.results || []).map(async row => {
      let poll = null;
      if (row.poll_id) {
        const [options,vote] = await Promise.all([
          env.DB.prepare("SELECT o.id,o.label,o.position,COUNT(v.user_id) AS votes FROM gomogie_poll_options o LEFT JOIN gomogie_poll_votes v ON v.option_id=o.id AND v.poll_id=o.poll_id WHERE o.poll_id=? GROUP BY o.id,o.label,o.position ORDER BY o.position").bind(row.poll_id).all(),
          auth ? env.DB.prepare("SELECT option_id FROM gomogie_poll_votes WHERE poll_id=? AND user_id=?").bind(row.poll_id,auth.sub).first() : Promise.resolve(null)
        ]);
        const total=(options.results||[]).reduce((sum,item)=>sum+Number(item.votes||0),0);
        poll={id:row.poll_id,closesAt:row.poll_closes_at,closed:!!row.poll_closes_at&&Date.parse(row.poll_closes_at)<=Date.now(),totalVotes:total,selectedOptionId:vote?.option_id||null,options:(options.results||[]).map(item=>({id:item.id,label:item.label,votes:Number(item.votes||0),percentage:total?Math.round(Number(item.votes||0)*100/total):0}))};
      }
      const attachments=await env.DB.prepare("SELECT media_type,media_id,video_id,position FROM gomogie_post_attachments WHERE post_id=? ORDER BY position ASC").bind(row.id).all();
      const mediaItems=(attachments.results||[]).map(item=>({type:item.media_type,id:item.media_type==="image"?item.media_id:item.video_id,url:item.media_type==="image"?mediaUrl(item.media_id):videoUrl(item.video_id),position:item.position}));
      return { id:row.id,content:row.content,visibility:row.visibility,createdAt:row.created_at,commentsEnabled:Boolean(row.comments_enabled),author:{id:row.user_id,username:row.username,displayName:row.display_name,avatarUrl:row.avatar_url,coverUrl:row.cover_url},mediaType:mediaItems[0]?.type||(poll?"poll":"text"),mediaUrl:mediaItems[0]?.url||"",mediaItems,reactionCount:row.reaction_count,commentCount:row.comment_count,poll };
    }));
    return json({ scope:followingFeedRequest?"following":"public",items });
  }

  const savedPostMatch = path.match(/^\/v1\/saved\/([0-9a-f-]+)$/i);
  if(path==="/v1/saved"&&method==="GET"){
    const rows=await env.DB.prepare(
      "SELECT p.id,p.user_id,p.content,p.visibility,p.created_at,p.comments_enabled,u.username,pr.display_name,pr.avatar_url,pr.cover_url,"+
      "(SELECT COUNT(*) FROM reactions r WHERE r.post_id=p.id) AS reaction_count,"+
      "(SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id AND c.status='published') AS comment_count,ma.id AS media_id,va.id AS video_id,gp.id AS poll_id,gp.closes_at AS poll_closes_at "+
      "FROM gomogie_saved_posts sp JOIN posts p ON p.id=sp.post_id JOIN users u ON u.id=p.user_id LEFT JOIN profiles pr ON pr.user_id=p.user_id "+
      "LEFT JOIN gomogie_post_media pm ON pm.post_id=p.id LEFT JOIN gomogie_media_assets ma ON ma.id=pm.media_id AND ma.status='ready' "+
      "LEFT JOIN gomogie_post_videos pv ON pv.post_id=p.id LEFT JOIN gomogie_video_assets va ON va.id=pv.video_id AND va.status='ready' "+
      "LEFT JOIN gomogie_polls gp ON gp.post_id=p.id WHERE sp.user_id=? AND p.status='published' ORDER BY sp.saved_at DESC LIMIT 200"
    ).bind(auth.sub).all();
    const items=await Promise.all((rows.results||[]).map(async row=>{
      let poll=null;
      if(row.poll_id){
        const [options,vote]=await Promise.all([
          env.DB.prepare("SELECT o.id,o.label,o.position,COUNT(v.user_id) AS votes FROM gomogie_poll_options o LEFT JOIN gomogie_poll_votes v ON v.option_id=o.id AND v.poll_id=o.poll_id WHERE o.poll_id=? GROUP BY o.id,o.label,o.position ORDER BY o.position").bind(row.poll_id).all(),
          env.DB.prepare("SELECT option_id FROM gomogie_poll_votes WHERE poll_id=? AND user_id=?").bind(row.poll_id,auth.sub).first()
        ]);
        const total=(options.results||[]).reduce((sum,item)=>sum+Number(item.votes||0),0);
        poll={id:row.poll_id,closesAt:row.poll_closes_at,closed:!!row.poll_closes_at&&Date.parse(row.poll_closes_at)<=Date.now(),totalVotes:total,selectedOptionId:vote?.option_id||null,options:(options.results||[]).map(item=>({id:item.id,label:item.label,votes:Number(item.votes||0),percentage:total?Math.round(Number(item.votes||0)*100/total):0}))};
      }
      const attachments=await env.DB.prepare("SELECT media_type,media_id,video_id,position FROM gomogie_post_attachments WHERE post_id=? ORDER BY position ASC").bind(row.id).all();
      const mediaItems=(attachments.results||[]).map(item=>({type:item.media_type,id:item.media_type==="image"?item.media_id:item.video_id,url:item.media_type==="image"?mediaUrl(item.media_id):videoUrl(item.video_id),position:item.position}));
      return {id:row.id,content:row.content,visibility:row.visibility,createdAt:row.created_at,commentsEnabled:Boolean(row.comments_enabled),author:{id:row.user_id,username:row.username,displayName:row.display_name,avatarUrl:row.avatar_url,coverUrl:row.cover_url},mediaType:mediaItems[0]?.type||(poll?"poll":"text"),mediaUrl:mediaItems[0]?.url||"",mediaItems,reactionCount:row.reaction_count,commentCount:row.comment_count,poll};
    }));
    return json({items});
  }
  if(savedPostMatch&&method==="POST"){
    const post=await env.DB.prepare("SELECT id FROM posts WHERE id=? AND status='published'").bind(savedPostMatch[1]).first();
    if(!post)return json({error:"post_not_found"},404);
    await env.DB.prepare("INSERT INTO gomogie_saved_posts (user_id,post_id,saved_at) VALUES (?,?,?) ON CONFLICT(user_id,post_id) DO NOTHING").bind(auth.sub,post.id,new Date().toISOString()).run();
    return json({saved:true,postId:post.id});
  }
  if(savedPostMatch&&method==="DELETE"){
    await env.DB.prepare("DELETE FROM gomogie_saved_posts WHERE user_id=? AND post_id=?").bind(auth.sub,savedPostMatch[1]).run();
    return json({saved:false,postId:savedPostMatch[1]});
  }

  const pollVoteMatch = path.match(/^\/v1\/posts\/([0-9a-f-]+)\/poll\/vote$/i);
  if (pollVoteMatch && method === "POST") {
    const input=await readJson(request),optionId=input?.optionId;
    if(!text(optionId,64))return json({error:"validation_error",message:"Pilih satu jawapan."},400);
    const poll=await env.DB.prepare("SELECT id,closes_at FROM gomogie_polls WHERE post_id=?").bind(pollVoteMatch[1]).first();
    if(!poll)return json({error:"poll_not_found"},404);
    if(poll.closes_at&&Date.parse(poll.closes_at)<=Date.now())return json({error:"poll_closed",message:"Poll ini telah ditutup."},409);
    const option=await env.DB.prepare("SELECT id FROM gomogie_poll_options WHERE id=? AND poll_id=?").bind(optionId,poll.id).first();
    if(!option)return json({error:"invalid_poll_option"},400);
    await env.DB.prepare("INSERT INTO gomogie_poll_votes (poll_id,option_id,user_id,created_at) VALUES (?,?,?,?) ON CONFLICT(poll_id,user_id) DO UPDATE SET option_id=excluded.option_id,created_at=excluded.created_at").bind(poll.id,optionId,auth.sub,new Date().toISOString()).run();
    return json({voted:true,pollId:poll.id,optionId});
  }

  if (path === "/v1/posts" && method === "POST") {
    const input = await readJson(request);
    const pollInput=input?.poll;
    const pollOptions=Array.isArray(pollInput?.options)?pollInput.options.map(x=>String(x||"").trim()).filter(Boolean):[];
    const hasPoll=!!pollInput;
    const requestedMedia=Array.isArray(input?.mediaItems)?input.mediaItems:(input?.mediaId?[{type:"image",id:input.mediaId}]:input?.videoId?[{type:"video",id:input.videoId}]:[]);
    if (!input || typeof input.content !== "string" || input.content.length > 5000 ||
        (!input.content.trim() && !requestedMedia.length && !hasPoll)) return json({error:"validation_error",message:"Tulis kandungan atau lampirkan media atau poll."},400);
    if(requestedMedia.length>10||requestedMedia.some(item=>!item||!["image","video"].includes(item.type)||!text(item.id,64))||new Set(requestedMedia.map(item=>item.id)).size!==requestedMedia.length)return json({error:"invalid_post_media",message:"Pilih maksimum 10 media yang sah dan elakkan fail berulang."},400);
    if(hasPoll&&requestedMedia.length)return json({error:"invalid_post_media",message:"Poll tidak boleh digabungkan dengan media dalam post yang sama."},400);
    if(hasPoll&&(pollOptions.length<2||pollOptions.length>6||pollOptions.some(x=>x.length>80)||new Set(pollOptions.map(x=>x.toLowerCase())).size!==pollOptions.length))return json({error:"invalid_poll",message:"Poll perlu 2 hingga 6 pilihan unik (maksimum 80 aksara setiap satu)."},400);
    let closesAt=null;
    if(hasPoll&&pollInput.durationHours!==undefined){const hours=Number(pollInput.durationHours);if(![1,6,12,24,72,168,720].includes(hours))return json({error:"invalid_poll_duration"},400);closesAt=new Date(Date.now()+hours*3600000).toISOString()}
    const visibility=["public","followers","private"].includes(input.visibility)?input.visibility:"public";
    const mentionNames=[...new Set([...input.content.matchAll(/(?:^|[\s(])@([A-Za-z0-9_]{3,24})\b/g)].map(m=>m[1].toLowerCase()))];
    let mentionRecipients=[];
    if(mentionNames.length){
      const marks=mentionNames.map(()=>"?").join(",");
      const found=await env.DB.prepare("SELECT id,username FROM users WHERE lower(username) IN ("+marks+") AND status='active'").bind(...mentionNames).all();
      const byName=new Map((found.results||[]).map(x=>[x.username.toLowerCase(),x]));
      const missing=mentionNames.filter(name=>!byName.has(name));
      if(missing.length)return json({error:"mention_user_not_found",message:"One or more mentioned users could not be found."},400);
      const ids=[...byName.values()].map(x=>x.id);
      const friendMarks=ids.map(()=>"?").join(",");
      const accepted=await env.DB.prepare("SELECT CASE WHEN requester_id=? THEN recipient_id ELSE requester_id END AS friend_id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND recipient_id IN ("+friendMarks+")) OR (recipient_id=? AND requester_id IN ("+friendMarks+")))").bind(auth.sub,auth.sub,...ids,auth.sub,...ids).all();
      const friendIds=new Set((accepted.results||[]).map(x=>x.friend_id));
      const blocked=[...byName.values()].filter(x=>x.id!==auth.sub&&!friendIds.has(x.id));
      if(blocked.length)return json({error:"mention_requires_friend",message:"You can mention friends only."},403);
      mentionRecipients=[...byName.values()].filter(x=>x.id!==auth.sub);
    }
    const id=uuid(),now=new Date().toISOString();
    const verifiedMedia=[];
    for(const [position,item] of requestedMedia.entries()){
      const asset=item.type==="image"
        ? await env.DB.prepare("SELECT id FROM gomogie_media_assets WHERE id=? AND owner_id=? AND purpose='post' AND status='ready'").bind(item.id,auth.sub).first()
        : await env.DB.prepare("SELECT id FROM gomogie_video_assets WHERE id=? AND owner_id=? AND status='ready'").bind(item.id,auth.sub).first();
      if(!asset)return json({error:item.type+"_not_found",message:"Salah satu media tidak ditemui, belum siap atau bukan milik akaun ini."},404);
      verifiedMedia.push({type:item.type,id:asset.id,position});
    }
    const statements=[env.DB.prepare("INSERT INTO posts (id,user_id,content,visibility,status,comments_enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)").bind(id,auth.sub,input.content.trim(),visibility,"published",input.commentsEnabled===false?0:1,now,now)];
    for(const item of verifiedMedia)statements.push(env.DB.prepare("INSERT INTO gomogie_post_attachments (id,post_id,media_type,media_id,video_id,position,created_at) VALUES (?,?,?,?,?,?,?)").bind(uuid(),id,item.type,item.type==="image"?item.id:null,item.type==="video"?item.id:null,item.position,now));
    let pollId=null;
    if(hasPoll){pollId=uuid();statements.push(env.DB.prepare("INSERT INTO gomogie_polls (id,post_id,closes_at,created_at) VALUES (?,?,?,?)").bind(pollId,id,closesAt,now));pollOptions.forEach((label,index)=>statements.push(env.DB.prepare("INSERT INTO gomogie_poll_options (id,poll_id,label,position) VALUES (?,?,?,?)").bind(uuid(),pollId,label,index)))}
    await env.DB.batch(statements);
    for(const recipient of mentionRecipients){
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)").bind(uuid(),recipient.id,auth.sub,"mention",id,now).run();
      await notifyPushDevices(env,recipient.id,{id,title:"You were mentioned on GomoGie",body:"A friend mentioned you in a post."});
    }
    const mediaItems=verifiedMedia.map(item=>({type:item.type,id:item.id,url:item.type==="image"?mediaUrl(item.id):videoUrl(item.id),position:item.position}));
    return json({post:{id,userId:auth.sub,content:input.content.trim(),visibility,status:"published",mediaType:mediaItems[0]?.type|| (hasPoll?"poll":"text"),mediaUrl:mediaItems[0]?.url||"",mediaItems,pollId,createdAt:now}},201);
  }

  const postDeleteMatch = path.match(/^\/v1\/posts\/([0-9a-f-]+)$/i);
  if (postDeleteMatch && method === "DELETE") {
    const owned = await env.DB.prepare("SELECT id FROM posts WHERE id=? AND user_id=? AND status='published'").bind(postDeleteMatch[1], auth.sub).first();
    if (!owned) return json({ error: "post_not_found", message: "Post tidak ditemui atau bukan milik akaun anda." }, 404);
    await env.DB.prepare("UPDATE posts SET status='deleted',updated_at=? WHERE id=? AND user_id=?").bind(new Date().toISOString(), postDeleteMatch[1], auth.sub).run();
    return json({ deleted: true, postId: postDeleteMatch[1] });
  }

  const postEditMatch = path.match(/^\/v1\/posts\/([0-9a-f-]+)$/i);
  if (postEditMatch && method === "PATCH") {
    const input = await readJson(request);
    if (!input || typeof input.content !== "string" || input.content.length > 5000) return json({ error: "validation_error", message: "Kandungan post tidak sah (maksimum 5,000 aksara)." }, 400);
    const owned = await env.DB.prepare("SELECT id FROM posts WHERE id=? AND user_id=? AND status='published'").bind(postEditMatch[1], auth.sub).first();
    if (!owned) return json({ error: "post_not_found", message: "Post tidak ditemui atau bukan milik akaun anda." }, 404);
    await env.DB.prepare("UPDATE posts SET content=?,updated_at=? WHERE id=? AND user_id=?").bind(input.content.trim(), new Date().toISOString(), postEditMatch[1], auth.sub).run();
    return json({ updated: true, postId: postEditMatch[1], content: input.content.trim() });
  }

  const reactionMatch = path.match(/^\/v1\/posts\/([0-9a-f-]+)\/reactions$/i);
  if (reactionMatch && method === "POST") {
    const input = await readJson(request) || {};
    const type = input.type || "like";
    if (!["like", "love", "haha", "wow", "sad", "angry"].includes(type)) return json({ error: "invalid_reaction" }, 400);
    const post = await env.DB.prepare("SELECT id,user_id FROM posts WHERE id=? AND status='published'").bind(reactionMatch[1]).first();
    if (!post) return json({ error: "post_not_found" }, 404);
    const previous = await env.DB.prepare("SELECT reaction_type FROM reactions WHERE user_id=? AND post_id=?").bind(auth.sub, reactionMatch[1]).first();
    await env.DB.prepare("INSERT INTO reactions (user_id,post_id,reaction_type) VALUES (?,?,?) ON CONFLICT(user_id,post_id) DO UPDATE SET reaction_type=excluded.reaction_type")
      .bind(auth.sub, reactionMatch[1], type).run();
    if (!previous && post.user_id !== auth.sub) {
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)")
        .bind(uuid(), post.user_id, auth.sub, "reaction", reactionMatch[1], new Date().toISOString()).run();
      await notifyPushDevices(env,post.user_id,{id:reactionMatch[1],title:"New reaction on GomoGie",body:"Someone reacted to your post."});
    }
    return json({ reaction: { postId: reactionMatch[1], type } });
  }
  if (reactionMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM reactions WHERE user_id=? AND post_id=?").bind(auth.sub, reactionMatch[1]).run();
    return new Response(null, { status: 204 });
  }

  const commentMatch = path.match(/^\/v1\/posts\/([0-9a-f-]+)\/comments$/i);
  if (commentMatch && method === "GET") {
    const post = await env.DB.prepare("SELECT id,visibility,status FROM posts WHERE id=?").bind(commentMatch[1]).first();
    if (!post || post.status !== "published" || post.visibility !== "public") return json({ error: "post_not_found" }, 404);
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const rows = await env.DB.prepare(
      "SELECT c.id,c.post_id,c.user_id,c.parent_id,c.content,c.created_at,u.username,p.display_name,p.avatar_url FROM comments c JOIN users u ON u.id=c.user_id LEFT JOIN profiles p ON p.user_id=c.user_id WHERE c.post_id=? AND c.status='published' ORDER BY c.created_at ASC LIMIT ?"
    ).bind(commentMatch[1], limit).all();
    return json({ items: (rows.results || []).map(row => ({ id: row.id, postId: row.post_id, userId: row.user_id, parentId: row.parent_id, content: row.content, createdAt: row.created_at, author: { username: row.username, displayName: row.display_name, avatarUrl: row.avatar_url } })) });
  }
  if (commentMatch && method === "POST") {
    const input = await readJson(request);
    if (!input || !text(input.content, 2000)) return json({ error: "validation_error" }, 400);
    const post = await env.DB.prepare("SELECT id,comments_enabled FROM posts WHERE id=? AND status='published'").bind(commentMatch[1]).first();
    if (!post) return json({ error: "post_not_found" }, 404);
    if (!post.comments_enabled) return json({ error: "comments_disabled" }, 403);
    const mentionNames=[...new Set([...input.content.matchAll(/(?:^|[\s(])@([A-Za-z0-9_]{3,24})\b/g)].map(m=>m[1].toLowerCase()))];
    let mentionRecipients=[];
    if(mentionNames.length){
      const marks=mentionNames.map(()=>"?").join(",");
      const found=await env.DB.prepare("SELECT id,username FROM users WHERE lower(username) IN ("+marks+") AND status='active'").bind(...mentionNames).all();
      const byName=new Map((found.results||[]).map(x=>[x.username.toLowerCase(),x]));
      if(mentionNames.some(name=>!byName.has(name)))return json({error:"mention_user_not_found",message:"One or more mentioned users could not be found."},400);
      const ids=[...byName.values()].map(x=>x.id);
      const friendMarks=ids.map(()=>"?").join(",");
      const accepted=await env.DB.prepare("SELECT CASE WHEN requester_id=? THEN recipient_id ELSE requester_id END AS friend_id FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND recipient_id IN ("+friendMarks+")) OR (recipient_id=? AND requester_id IN ("+friendMarks+")))").bind(auth.sub,auth.sub,...ids,auth.sub,...ids).all();
      const friendIds=new Set((accepted.results||[]).map(x=>x.friend_id));
      const blocked=[...byName.values()].filter(x=>x.id!==auth.sub&&!friendIds.has(x.id));
      if(blocked.length)return json({error:"mention_requires_friend",message:"You can mention friends only."},403);
      mentionRecipients=[...byName.values()].filter(x=>x.id!==auth.sub);
    }
    let parent = null;
    if (input.parentId) {
      parent = await env.DB.prepare("SELECT id,user_id FROM comments WHERE id=? AND post_id=? AND status='published'")
        .bind(input.parentId, commentMatch[1]).first();
      if (!parent) return json({ error: "parent_comment_not_found", message: "Reply asal tidak ditemui dalam perbualan ini." }, 404);
    }
    const id = uuid(), now = new Date().toISOString();
    await env.DB.prepare("INSERT INTO comments (id,post_id,user_id,parent_id,content,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)")
      .bind(id, commentMatch[1], auth.sub, parent?.id || null, input.content.trim(), "published", now, now).run();
    const owner = await env.DB.prepare("SELECT user_id FROM posts WHERE id=?").bind(commentMatch[1]).first();
    const mentionedIds=new Set(mentionRecipients.map(x=>x.id));
    const recipients = new Set([owner?.user_id, parent?.user_id].filter(userId => userId && userId !== auth.sub && !mentionedIds.has(userId)));
    for (const recipientId of recipients) {
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)")
        .bind(uuid(), recipientId, auth.sub, "comment", commentMatch[1], now).run();
      await notifyPushDevices(env,recipientId,{id:commentMatch[1],title:"New reply on GomoGie",body:"Someone replied to a post you’re part of."});
    }
    for(const recipient of mentionRecipients){
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)").bind(uuid(),recipient.id,auth.sub,"mention",commentMatch[1],now).run();
      await notifyPushDevices(env,recipient.id,{id:commentMatch[1],title:"You were mentioned on GomoGie",body:"A friend mentioned you in a reply."});
    }
    return json({ comment: { id, postId: commentMatch[1], userId: auth.sub, parentId: parent?.id || null, content: input.content.trim(), createdAt: now } }, 201);
  }

  // Friends are explicit two-way relationships; follows remain independent one-way relationships.
  if (path === "/v1/users/search" && method === "GET") {
    const q=(url.searchParams.get("q")||"").trim().replace(/^@/,"").slice(0,24);
    if(q.length<2)return json({items:[]});
    const friendsOnly=url.searchParams.get("scope")==="mentions";
    const sql="SELECT u.id,u.username,p.display_name,p.avatar_url FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.status='active' AND u.id<>? AND (u.username LIKE ? OR p.display_name LIKE ?)"+(friendsOnly?" AND EXISTS (SELECT 1 FROM friend_requests fr WHERE fr.status='accepted' AND ((fr.requester_id=? AND fr.recipient_id=u.id) OR (fr.recipient_id=? AND fr.requester_id=u.id)))":"")+" ORDER BY CASE WHEN u.username=? COLLATE NOCASE THEN 0 ELSE 1 END,u.username LIMIT 20";
    const rows=friendsOnly?await env.DB.prepare(sql).bind(auth.sub,"%"+q+"%","%"+q+"%",auth.sub,auth.sub,q).all():await env.DB.prepare(sql).bind(auth.sub,"%"+q+"%","%"+q+"%",q).all();
    return json({items:(rows.results||[]).map(x=>({id:x.id,username:x.username,displayName:x.display_name||x.username,avatarUrl:x.avatar_url||""}))});
  }
  if (path === "/v1/friends" && method === "GET") {
    const rows=await env.DB.prepare("SELECT u.id,u.username,p.display_name,p.avatar_url,fr.created_at AS since FROM friend_requests fr JOIN users u ON u.id=CASE WHEN fr.requester_id=? THEN fr.recipient_id ELSE fr.requester_id END LEFT JOIN profiles p ON p.user_id=u.id WHERE fr.status='accepted' AND (fr.requester_id=? OR fr.recipient_id=?) AND u.status='active' ORDER BY fr.updated_at DESC LIMIT 500").bind(auth.sub,auth.sub,auth.sub).all();
    return json({items:(rows.results||[]).map(x=>({id:x.id,username:x.username,displayName:x.display_name||x.username,avatarUrl:x.avatar_url||"",since:x.since}))});
  }
  if (path === "/v1/friend-requests" && method === "GET") {
    const rows=await env.DB.prepare("SELECT fr.id,fr.requester_id,fr.recipient_id,fr.created_at,u.username,p.display_name,p.avatar_url FROM friend_requests fr JOIN users u ON u.id=CASE WHEN fr.recipient_id=? THEN fr.requester_id ELSE fr.recipient_id END LEFT JOIN profiles p ON p.user_id=u.id WHERE fr.status='pending' AND (fr.recipient_id=? OR fr.requester_id=?) AND u.status='active' ORDER BY fr.created_at DESC LIMIT 100").bind(auth.sub,auth.sub,auth.sub).all();
    return json({items:(rows.results||[]).map(x=>({id:x.id,direction:x.recipient_id===auth.sub?"incoming":"outgoing",createdAt:x.created_at,person:{id:x.requester_id===auth.sub?x.recipient_id:x.requester_id,username:x.username,displayName:x.display_name||x.username,avatarUrl:x.avatar_url||""}}))});
  }
  const friendRequestMatch=path.match(/^\/v1\/users\/([a-zA-Z0-9_]{3,24})\/friend-request$/);
  if(friendRequestMatch&&method==="POST"){
    const target=await env.DB.prepare("SELECT id,username FROM users WHERE username=? COLLATE NOCASE AND status='active'").bind(friendRequestMatch[1]).first();
    if(!target)return json({error:"user_not_found",message:"Pengguna tidak ditemui."},404);
    if(target.id===auth.sub)return json({error:"cannot_friend_self"},400);
    const pair=await env.DB.prepare("SELECT id,status,requester_id,recipient_id FROM friend_requests WHERE (requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?) LIMIT 1").bind(auth.sub,target.id,target.id,auth.sub).first();
    if(pair?.status==="accepted")return json({friend:true,alreadyFriends:true});
    const now=new Date().toISOString();
    if(pair?.status==="pending"&&pair.recipient_id===auth.sub){
      await env.DB.prepare("UPDATE friend_requests SET status='accepted',updated_at=? WHERE id=?").bind(now,pair.id).run();
      try{await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)").bind(uuid(),pair.requester_id,auth.sub,"friend_accepted",pair.id,now).run();}catch(error){console.error("Reciprocal friend acceptance notification failed",pair.id,error);}
      try{await notifyPushDevices(env,pair.requester_id,{id:pair.id,title:"Friend request accepted",body:"Your friend request was accepted."});}catch(error){console.error("Reciprocal friend acceptance push failed",pair.id,error);}
      return json({friend:true,accepted:true});
    }
    if(pair?.status==="pending")return json({requestSent:true,pending:true});
    const id=uuid();
    await env.DB.prepare("INSERT INTO friend_requests (id,requester_id,recipient_id,status,created_at,updated_at) VALUES (?,?,?,'pending',?,?) ON CONFLICT(requester_id,recipient_id) DO UPDATE SET status='pending',created_at=excluded.created_at,updated_at=excluded.updated_at").bind(id,auth.sub,target.id,now,now).run();
    await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)").bind(uuid(),target.id,auth.sub,"friend_request",id,now).run();
    await notifyPushDevices(env,target.id,{id,title:"New friend request",body:"Someone sent you a friend request on GomoGie."});
    return json({requestSent:true,status:"pending"},201);
  }
  const friendRequestAction=path.match(/^\/v1\/friend-requests\/([0-9a-f-]+)\/(accept|decline)$/i);
  if(friendRequestAction&&method==="POST"){
    const requestRow=await env.DB.prepare("SELECT id,requester_id,recipient_id,status FROM friend_requests WHERE id=?").bind(friendRequestAction[1]).first();
    if(!requestRow||requestRow.recipient_id!==auth.sub||requestRow.status!=="pending")return json({error:"request_not_found"},404);
    const accept=friendRequestAction[2].toLowerCase()==="accept",now=new Date().toISOString();
    await env.DB.prepare("UPDATE friend_requests SET status=?,updated_at=? WHERE id=? AND recipient_id=? AND status='pending'").bind(accept?"accepted":"declined",now,requestRow.id,auth.sub).run();
    if(accept){
      try{
        await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)").bind(uuid(),requestRow.requester_id,auth.sub,"friend_accepted",requestRow.id,now).run();
      }catch(error){console.error("Friend acceptance in-app notification failed",requestRow.id,error);}
      try{
        await notifyPushDevices(env,requestRow.requester_id,{id:requestRow.id,title:"Friend request accepted",body:"Your friend request was accepted."});
      }catch(error){console.error("Friend acceptance push notification failed",requestRow.id,error);}
    }
    return json({accepted:accept});
  }
  const friendRemove=path.match(/^\/v1\/friends\/([a-zA-Z0-9_]{3,24})$/);
  if(friendRemove&&method==="DELETE"){
    const target=await env.DB.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE AND status='active'").bind(friendRemove[1]).first();
    if(!target)return json({error:"user_not_found"},404);
    await env.DB.prepare("DELETE FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?))").bind(auth.sub,target.id,target.id,auth.sub).run();
    return json({friend:false});
  }

  if (path === "/v1/users/me/following" && method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT f.following_id,u.username,f.status FROM follows f " +
      "JOIN users u ON u.id=f.following_id " +
      "WHERE f.follower_id=? AND f.status IN ('accepted','pending') " +
      "ORDER BY f.created_at DESC LIMIT 500"
    ).bind(auth.sub).all();
    return json({ items: (rows.results || []).map(row => ({
      id: row.following_id, username: row.username, status: row.status
    })) });
  }

  const relationshipMatch = path.match(/^\/v1\/users\/([a-zA-Z0-9_]{3,24})\/(relationships|followers|following|friends)$/);
  if (relationshipMatch && method === "GET") {
    const target = await env.DB.prepare("SELECT id FROM users WHERE username=? COLLATE NOCASE AND status='active'").bind(relationshipMatch[1]).first();
    if (!target) return json({ error: "user_not_found" }, 404);
    const kind = relationshipMatch[2];
    if (kind === "relationships") {
      const [followers, following, friends] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) AS count FROM follows WHERE following_id=? AND status='accepted'").bind(target.id).first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM follows WHERE follower_id=? AND status='accepted'").bind(target.id).first(),
        env.DB.prepare("SELECT COUNT(*) AS count FROM friend_requests WHERE status='accepted' AND (requester_id=? OR recipient_id=?)").bind(target.id,target.id).first()
      ]);
      return json({ followers: Number(followers?.count || 0), following: Number(following?.count || 0), friends: Number(friends?.count || 0) });
    }
    if(kind==="friends"){
      const rows=await env.DB.prepare("SELECT u.id,u.username,p.display_name,p.avatar_url,fr.updated_at AS since FROM friend_requests fr JOIN users u ON u.id=CASE WHEN fr.requester_id=? THEN fr.recipient_id ELSE fr.requester_id END LEFT JOIN profiles p ON p.user_id=u.id WHERE fr.status='accepted' AND (fr.requester_id=? OR fr.recipient_id=?) AND u.status='active' ORDER BY fr.updated_at DESC LIMIT 200").bind(target.id,target.id,target.id).all();
      return json({items:(rows.results||[]).map(row=>({id:row.id,username:row.username,displayName:row.display_name||row.username,avatarUrl:row.avatar_url||"",since:row.since}))});
    }
    const column = kind === "followers" ? "following_id" : "follower_id";
    const joinColumn = kind === "followers" ? "follower_id" : "following_id";
    const rows = await env.DB.prepare("SELECT u.id,u.username,p.display_name,p.avatar_url FROM follows f JOIN users u ON u.id=f." + joinColumn + " LEFT JOIN profiles p ON p.user_id=u.id WHERE f." + column + "=? AND f.status='accepted' AND u.status='active' ORDER BY f.created_at DESC LIMIT 200").bind(target.id).all();
    return json({ items: (rows.results || []).map(row => ({ id: row.id, username: row.username, displayName: row.display_name || row.username, avatarUrl: row.avatar_url || "" })) });
  }

  const followMatch = path.match(/^\/v1\/users\/([a-zA-Z0-9_]{3,24})\/follow$/);
  if (followMatch && method === "POST") {
    const target = await env.DB.prepare("SELECT u.id,p.is_private FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.username=? COLLATE NOCASE AND u.status='active'")
      .bind(followMatch[1]).first();
    if (!target) return json({ error: "user_not_found" }, 404);
    if (target.id === auth.sub) return json({ error: "cannot_follow_self" }, 400);
    const status = target.is_private ? "pending" : "accepted";
    const existingFollow = await env.DB.prepare("SELECT status FROM follows WHERE follower_id=? AND following_id=?").bind(auth.sub, target.id).first();
    await env.DB.prepare("INSERT INTO follows (follower_id,following_id,status) VALUES (?,?,?) ON CONFLICT(follower_id,following_id) DO UPDATE SET status=excluded.status")
      .bind(auth.sub, target.id, status).run();
    if (!existingFollow && status === "accepted") {
      await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)")
        .bind(uuid(), target.id, auth.sub, "follow", auth.sub, new Date().toISOString()).run();
      await notifyPushDevices(env,target.id,{id:auth.sub,title:"New follower on GomoGie",body:"Someone started following you."});
    }
    return json({ following: true, status });
  }
  if (followMatch && method === "DELETE") {
    await env.DB.prepare("DELETE FROM follows WHERE follower_id=? AND following_id=(SELECT id FROM users WHERE username=? COLLATE NOCASE)")
      .bind(auth.sub, followMatch[1]).run();
    return new Response(null, { status: 204 });
  }


  if(path==="/v1/message-requests"&&method==="GET"){
    const rows=await env.DB.prepare("SELECT c.id,mr.requester_id,mr.recipient_id,mr.created_at,other.user_id AS other_id,u.username,p.display_name,p.avatar_url,(SELECT m.content FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at ASC LIMIT 1) AS first_message FROM gomogie_message_requests mr JOIN conversations c ON c.id=mr.conversation_id JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? JOIN conversation_members other ON other.conversation_id=c.id AND other.user_id<>? LEFT JOIN users u ON u.id=other.user_id LEFT JOIN profiles p ON p.user_id=other.user_id WHERE mr.status='pending' ORDER BY mr.created_at DESC LIMIT 100").bind(auth.sub,auth.sub).all();
    return json({items:(rows.results||[]).map(x=>({id:x.id,direction:x.requester_id===auth.sub?"outgoing":"incoming",createdAt:x.created_at,firstMessage:x.first_message||"",participant:{id:x.other_id,username:x.username,displayName:x.display_name||x.username,avatarUrl:x.avatar_url||""}}))});
  }
  const messageRequestAction=path.match(/^\/v1\/conversations\/([0-9a-f-]+)\/(accept|decline)$/i);
  if(messageRequestAction&&method==="POST"){
    const id=messageRequestAction[1],action=messageRequestAction[2].toLowerCase();
    const row=await env.DB.prepare("SELECT status,requester_id,recipient_id FROM gomogie_message_requests WHERE conversation_id=?").bind(id).first();
    if(!row||row.status!=="pending")return json({error:"request_not_found"},404);
    if(action==="accept"){
      if(row.recipient_id!==auth.sub)return json({error:"request_not_found"},404);
      const now=new Date().toISOString();
      await env.DB.prepare("UPDATE gomogie_message_requests SET status='accepted',decided_at=? WHERE conversation_id=? AND status='pending'").bind(now,id).run();
      try{await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)").bind(uuid(),row.requester_id,auth.sub,"message_request_accepted",id,now).run();}catch(error){console.error("Message request acceptance notification failed",id,error);}
      try{await notifyPushDevices(env,row.requester_id,{id,title:"Message request accepted",body:"Your message request was accepted."});}catch(error){console.error("Message request acceptance push failed",id,error);}
      return json({accepted:true});
    }
    if(row.recipient_id!==auth.sub&&row.requester_id!==auth.sub)return json({error:"request_not_found"},404);
    await env.DB.batch([env.DB.prepare("DELETE FROM gomogie_message_requests WHERE conversation_id=?").bind(id),env.DB.prepare("DELETE FROM messages WHERE conversation_id=?").bind(id),env.DB.prepare("DELETE FROM conversation_members WHERE conversation_id=?").bind(id),env.DB.prepare("DELETE FROM conversations WHERE id=?").bind(id)]);
    return json({declined:true});
  }
  if (path === "/v1/conversations" && method === "GET") {
    const rows = await env.DB.prepare(
      "SELECT c.id,c.type,c.title,c.created_at,other.user_id AS other_id,u.username,p.display_name,p.avatar_url," +
      "(SELECT m.content FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message," +
      "(SELECT m.created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message_at," +
      "(SELECT COUNT(*) FROM messages m WHERE m.conversation_id=c.id AND m.sender_id<>? AND m.created_at>COALESCE(mine.last_read_at,'1970-01-01T00:00:00.000Z')) AS unread_count " +
      "FROM conversations c JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? " +
      "JOIN conversation_members other ON other.conversation_id=c.id AND other.user_id<>? " +
      "LEFT JOIN users u ON u.id=other.user_id LEFT JOIN profiles p ON p.user_id=other.user_id " +
      "WHERE c.type='direct' AND NOT EXISTS (SELECT 1 FROM gomogie_message_requests mr WHERE mr.conversation_id=c.id AND mr.status='pending') ORDER BY COALESCE(last_message_at,c.created_at) DESC LIMIT 100"
    ).bind(auth.sub, auth.sub, auth.sub).all();
    return json({ items: (rows.results || []).map(row => ({
      id: row.id, type: row.type, title: row.title,
      createdAt: row.created_at, lastMessage: row.last_message || "",
      lastMessageAt: row.last_message_at || row.created_at,
      unreadCount: Number(row.unread_count || 0),
      participant: { id: row.other_id, username: row.username, displayName: row.display_name || row.username, avatarUrl: row.avatar_url }
    })) });
  }

  if (path === "/v1/conversations" && method === "POST") {
    const input = await readJson(request);
    if (!input || !text(input.username, 24) || !/^[a-zA-Z0-9_]{3,24}$/.test(input.username.trim())) {
      return json({ error: "validation_error", message: "Username penerima tidak sah." }, 400);
    }
    const recipient = await env.DB.prepare(
      "SELECT id,username FROM users WHERE username=? COLLATE NOCASE AND status='active'"
    ).bind(input.username.trim()).first();
    if (!recipient) return json({ error: "user_not_found", message: "Pengguna tidak ditemui." }, 404);
    if (recipient.id === auth.sub) return json({ error: "cannot_message_self", message: "Anda tidak boleh memulakan perbualan dengan akaun sendiri." }, 400);
    let existing = await env.DB.prepare(
      "SELECT c.id,(SELECT mr.status FROM gomogie_message_requests mr WHERE mr.conversation_id=c.id) AS status FROM conversations c " +
      "JOIN conversation_members mine ON mine.conversation_id=c.id AND mine.user_id=? " +
      "JOIN conversation_members other ON other.conversation_id=c.id AND other.user_id=? " +
      "WHERE c.type='direct' AND (SELECT COUNT(*) FROM conversation_members all_members WHERE all_members.conversation_id=c.id)=2 LIMIT 1"
    ).bind(auth.sub, recipient.id).first();
    if (existing) return json({ conversation: { id: existing.id }, created: false, status: existing.status || "accepted" });
    const friendship=await env.DB.prepare("SELECT 1 AS ok FROM friend_requests WHERE status='accepted' AND ((requester_id=? AND recipient_id=?) OR (requester_id=? AND recipient_id=?)) LIMIT 1").bind(auth.sub,recipient.id,recipient.id,auth.sub).first();
    const status=friendship?"accepted":"pending";
    const id = uuid(), now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO conversations (id,type,title,created_by,created_at) VALUES (?,'direct',NULL,?,?)").bind(id, auth.sub, now),
      env.DB.prepare("INSERT INTO conversation_members (conversation_id,user_id,joined_at,last_read_at) VALUES (?,?,?,?)").bind(id, auth.sub, now, now),
      env.DB.prepare("INSERT INTO conversation_members (conversation_id,user_id,joined_at,last_read_at) VALUES (?,?,?,NULL)").bind(id, recipient.id, now),
      ...(friendship?[]:[env.DB.prepare("INSERT INTO gomogie_message_requests (id,conversation_id,requester_id,recipient_id,status,created_at) VALUES (?,?,?,?,'pending',?)").bind(uuid(),id,auth.sub,recipient.id,now)])
    ]);
    return json({ conversation: { id }, created: true, status }, 201);
  }

  const conversationMessagesMatch = path.match(/^\/v1\/conversations\/([0-9a-f-]+)\/messages$/i);
  if (conversationMessagesMatch) {
    const conversationId = conversationMessagesMatch[1];
    const membership = await env.DB.prepare(
      "SELECT conversation_id FROM conversation_members WHERE conversation_id=? AND user_id=?"
    ).bind(conversationId, auth.sub).first();
    if (!membership) return json({ error: "conversation_not_found" }, 404);
    if (method === "GET") {
      const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") || 50)));
      const rows = await env.DB.prepare(
        "SELECT m.id,m.conversation_id,m.sender_id,m.content,m.media_id,m.status,m.created_at,m.edited_at,u.username,p.display_name,p.avatar_url " +
        "FROM messages m JOIN users u ON u.id=m.sender_id LEFT JOIN profiles p ON p.user_id=m.sender_id " +
        "WHERE m.conversation_id=? ORDER BY m.created_at DESC LIMIT ?"
      ).bind(conversationId, limit).all();
      const now = new Date().toISOString();
      await env.DB.prepare("UPDATE conversation_members SET last_read_at=? WHERE conversation_id=? AND user_id=?").bind(now, conversationId, auth.sub).run();
      const messages=[];
      for(const row of (rows.results||[]).reverse()){
        const attached=await env.DB.prepare("SELECT a.attachment_type,a.media_id,a.video_id,a.file_id,f.file_name FROM gomogie_message_attachments a LEFT JOIN gomogie_message_files f ON f.id=a.file_id WHERE a.message_id=? ORDER BY a.position ASC").bind(row.id).all();
        const attachments=(attached.results||[]).map(item=>({type:item.attachment_type,id:item.media_id||item.video_id||item.file_id,url:item.attachment_type==="image"?mediaUrl(item.media_id):item.attachment_type==="video"?videoUrl(item.video_id):"/v1/message-files/"+item.file_id,downloadUrl:item.attachment_type==="file"?"/v1/message-files/"+item.file_id+"?download=1":null}));
        messages.push({id:row.id,conversationId:row.conversation_id,senderId:row.sender_id,content:row.content,mediaId:row.media_id,attachments,status:row.status,createdAt:row.created_at,editedAt:row.edited_at,sender:{username:row.username,displayName:row.display_name||row.username,avatarUrl:row.avatar_url}});
      }
      return json({items:messages});
    }
    if (method === "POST") {
      const requestRow=await env.DB.prepare("SELECT requester_id,status FROM gomogie_message_requests WHERE conversation_id=?").bind(conversationId).first();
      if(requestRow?.status==="pending"){
        const count=await env.DB.prepare("SELECT COUNT(*) AS count FROM messages WHERE conversation_id=?").bind(conversationId).first();
        if(requestRow.requester_id!==auth.sub||Number(count?.count||0)>0)return json({error:"message_request_pending",message:"Mesej seterusnya hanya boleh dihantar selepas penerima menerima permintaan ini."},403);
      }
      const input = await readJson(request);
      const attachments=Array.isArray(input?.attachments)?input.attachments:[];
      if (!input || (typeof input.content!=="string") || input.content.length>4000 || (!input.content.trim()&&!attachments.length) || attachments.length>10) return json({ error: "validation_error", message: "Tulis mesej atau lampirkan fail (maksimum 10 lampiran)." }, 400);
      const id = uuid(), now = new Date().toISOString();
      const verified=[];
      for(const [position,item] of attachments.entries()){
        if(!item||!["image","video","file"].includes(item.type)||!text(item.id,64))return json({error:"invalid_attachment"},400);
        const table=item.type==="image"?"gomogie_media_assets":item.type==="video"?"gomogie_video_assets":"gomogie_message_files";
        const owner=await env.DB.prepare("SELECT id FROM "+table+" WHERE id=? AND owner_id=?"+(item.type==="image"?" AND purpose='message'":"")+(item.type!=="file"?" AND status='ready'":"")).bind(item.id,auth.sub).first();
        if(!owner)return json({error:"attachment_not_found",message:"Lampiran tidak sah atau bukan milik akaun ini."},404);
        verified.push({...item,position});
      }
      await env.DB.prepare(
        "INSERT INTO messages (id,conversation_id,sender_id,content,media_id,status,created_at,edited_at) VALUES (?,?,?,?,NULL,'sent',?,NULL)"
      ).bind(id, conversationId, auth.sub, input.content.trim(), now).run();
      for(const item of verified)await env.DB.prepare("INSERT INTO gomogie_message_attachments (id,message_id,attachment_type,media_id,video_id,file_id,position,created_at) VALUES (?,?,?,?,?,?,?,?)").bind(uuid(),id,item.type,item.type==="image"?item.id:null,item.type==="video"?item.id:null,item.type==="file"?item.id:null,item.position,now).run();
      const recipient=await env.DB.prepare("SELECT user_id FROM conversation_members WHERE conversation_id=? AND user_id<>? LIMIT 1").bind(conversationId,auth.sub).first();
      if(recipient){
        const isPendingRequest=requestRow?.status==="pending";
        const preview=input.content.trim().replace(/\s+/g," ").slice(0,120);
        const title=isPendingRequest?"New message request":"New message";
        const body=isPendingRequest?"Message request: "+preview:preview;
        try{await env.DB.prepare("INSERT INTO notifications (id,recipient_id,actor_id,type,entity_id,is_read,created_at) VALUES (?,?,?,?,?,0,?)").bind(uuid(),recipient.user_id,auth.sub,isPendingRequest?"message_request":"message",conversationId,now).run();}catch(error){console.error("New message in-app notification failed",conversationId,error);}
        try{await notifyPushDevices(env,recipient.user_id,{id,title,body});}catch(error){console.error("New message push notification failed",conversationId,error);}
      }
      return json({ message: { id, conversationId, senderId: auth.sub, content: input.content.trim(), mediaId: null, status: "sent", createdAt: now } }, 201);
    }
  }

  return json({ error: "not_found" }, 404);
}

async function processAccountDeletionQueue(env) {
  const due = await env.DB.prepare("SELECT user_id FROM gomogie_account_deletion_requests WHERE status='pending' AND scheduled_for<=? LIMIT 25").bind(new Date().toISOString()).all();
  let completed = 0, failed = 0;
  for (const item of due.results || []) {
    const userId = item.user_id;
    try {
      const images = await env.DB.prepare("SELECT object_key FROM gomogie_media_assets WHERE owner_id=?").bind(userId).all();
      const videos = await env.DB.prepare("SELECT object_key FROM gomogie_video_assets WHERE owner_id=?").bind(userId).all();
      const mediaObjects = [...(images.results || []), ...(videos.results || [])];
      // Fail closed: never erase D1 ownership records if R2 cannot be reached.
      if (mediaObjects.length && !env.MEDIA_BUCKET) throw new Error("R2_MEDIA_BUCKET_UNAVAILABLE");
      if (env.MEDIA_BUCKET) {
        for (const asset of mediaObjects) {
          if (!asset.object_key) throw new Error("R2_MEDIA_OBJECT_KEY_MISSING");
          await env.MEDIA_BUCKET.delete(asset.object_key);
        }
      }
      await env.DB.batch([
        env.DB.prepare("DELETE FROM posts WHERE user_id=?").bind(userId),
        env.DB.prepare("DELETE FROM comments WHERE user_id=?").bind(userId),
        env.DB.prepare("DELETE FROM reactions WHERE user_id=?").bind(userId),
        env.DB.prepare("DELETE FROM follows WHERE follower_id=? OR following_id=?").bind(userId,userId),
        env.DB.prepare("DELETE FROM notifications WHERE recipient_id=? OR actor_id=?").bind(userId,userId),
        env.DB.prepare("DELETE FROM messages WHERE sender_id=?").bind(userId),
        env.DB.prepare("DELETE FROM conversation_members WHERE user_id=?").bind(userId),
        env.DB.prepare("DELETE FROM gomogie_news_preferences WHERE user_id=?").bind(userId),
        env.DB.prepare("DELETE FROM gomogie_media_assets WHERE owner_id=?").bind(userId),
        env.DB.prepare("DELETE FROM gomogie_video_assets WHERE owner_id=?").bind(userId)
      ]);
      const owned = await env.DB.prepare("SELECT id FROM communities WHERE owner_id=?").bind(userId).all().catch(()=>({results:[]}));
      for (const community of owned.results || []) { try { await env.DB.prepare("DELETE FROM communities WHERE id=?").bind(community.id).run(); } catch (error) { console.warn("Community cleanup deferred", community.id, error); } }
      const suffix = crypto.randomUUID().replace(/-/g,"").slice(0,16), erasedPassword = await passwordHash(crypto.randomUUID()+crypto.randomUUID()), now = new Date().toISOString();
      await env.DB.batch([
        env.DB.prepare("UPDATE profiles SET display_name='Deleted member',bio='',avatar_url=NULL,cover_url=NULL,website='',location='',is_private=1,updated_at=? WHERE user_id=?").bind(now,userId),
        env.DB.prepare("UPDATE users SET email=?,username=?,password_hash=?,status='deleted',updated_at=? WHERE id=?").bind("deleted+"+suffix+"@deleted.invalid","deleted_"+suffix,erasedPassword,now,userId),
        env.DB.prepare("UPDATE gomogie_account_deletion_requests SET status='completed' WHERE user_id=?").bind(userId)
      ]);
      completed++;
    } catch (error) { failed++; console.error("Account deletion failed", userId, error); }
  }
  return { checked:(due.results||[]).length, completed, failed };
}


function pushB64(bytes){return b64url(bytes)}
function pushUnb64(value){return fromB64url(value)}
async function hkdfBits(ikm,salt,info,length){
 const key=await crypto.subtle.importKey("raw",ikm,"HKDF",false,["deriveBits"]);
 return new Uint8Array(await crypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt,info},key,length*8));
}
async function sendWebPush(subscription,payload,env){
 if(!env.VAPID_PRIVATE_JWK||!env.VAPID_PUBLIC_KEY||!env.VAPID_SUBJECT)return false;
 const endpoint=new URL(subscription.endpoint),audience=endpoint.origin,now=Math.floor(Date.now()/1000);
 const header=pushB64(encoder.encode(JSON.stringify({typ:"JWT",alg:"ES256"})));
 const claims=pushB64(encoder.encode(JSON.stringify({aud:audience,exp:now+43200,sub:env.VAPID_SUBJECT})));
 const signingInput=header+"."+claims;
 const vapidKey=await crypto.subtle.importKey("jwk",JSON.parse(env.VAPID_PRIVATE_JWK),{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
 const signature=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},vapidKey,encoder.encode(signingInput)));
 const receiver=pushUnb64(subscription.p256dh),auth=pushUnb64(subscription.auth_secret);
 const serverPair=await crypto.subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 const serverPublic=new Uint8Array(await crypto.subtle.exportKey("raw",serverPair.publicKey));
 const receiverKey=await crypto.subtle.importKey("raw",receiver,{name:"ECDH",namedCurve:"P-256"},false,[]);
 const shared=new Uint8Array(await crypto.subtle.deriveBits({name:"ECDH",public:receiverKey},serverPair.privateKey,256));
 const keyInfo=new Uint8Array([...encoder.encode("WebPush: info\0"),...receiver,...serverPublic]);
 const ikm=await hkdfBits(shared,auth,keyInfo,32);
 const salt=crypto.getRandomValues(new Uint8Array(16));
 const cek=await hkdfBits(ikm,salt,encoder.encode("Content-Encoding: aes128gcm\0"),16);
 const nonce=await hkdfBits(ikm,salt,encoder.encode("Content-Encoding: nonce\0"),12);
 const plain=encoder.encode(JSON.stringify(payload));
 const record=new Uint8Array(plain.length+1);record.set(plain);record[plain.length]=2;
 const aes=await crypto.subtle.importKey("raw",cek,{name:"AES-GCM"},false,["encrypt"]);
 const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce,tagLength:128},aes,record));
 const body=new Uint8Array(16+4+1+serverPublic.length+encrypted.length),view=new DataView(body.buffer);
 body.set(salt,0);view.setUint32(16,4096);body[20]=serverPublic.length;body.set(serverPublic,21);body.set(encrypted,21+serverPublic.length);
 const response=await fetch(subscription.endpoint,{method:"POST",headers:{
  "TTL":"86400","Urgency":"normal","Content-Encoding":"aes128gcm","Content-Type":"application/octet-stream",
  "Authorization":"vapid t="+signingInput+"."+pushB64(signature)+", k="+env.VAPID_PUBLIC_KEY
 },body});
 if(response.status===404||response.status===410)return "expired";
 if(!response.ok)throw new Error("Web Push endpoint returned "+response.status);
 return true;
}
async function notifyPushDevices(env,userId,notification){
 if(!env.VAPID_PRIVATE_JWK||!env.VAPID_PUBLIC_KEY||!env.VAPID_SUBJECT)return;
 const rows=await env.DB.prepare("SELECT id,endpoint,p256dh,auth_secret FROM gomogie_push_subscriptions WHERE user_id=?").bind(userId).all();
 for(const row of rows.results||[]){try{const result=await sendWebPush(row,{title:notification.title||"GomoGie",body:notification.body||"You have a new notification.",url:"./",tag:notification.id||"gomogie"},env);if(result==="expired")await env.DB.prepare("DELETE FROM gomogie_push_subscriptions WHERE id=?").bind(row.id).run()}catch(error){console.error("Push delivery failed",row.id,error)}}
}

export default {
  async scheduled(controller, env, ctx) { ctx.waitUntil((async()=>{try{const sync=await syncNewsFeeds(env);console.log("GomoGie scheduled news sync",sync)}catch(error){console.error("GomoGie news sync failed",error)}try{const images=await hydrateRecentNewsImages(env,12);console.log("GomoGie scheduled news image hydration",images)}catch(error){console.error("GomoGie news image hydration failed",error)}try{const deletions=await processAccountDeletionQueue(env);console.log("GomoGie account deletion processing",deletions)}catch(error){console.error("GomoGie account deletion processing failed",error)}})()); },
  async fetch(request, env) {
    const headers = corsHeaders(request, env);
    if (request.method === "OPTIONS") {
      if (!Object.keys(headers).length) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers });
    }
    try {
      const requestUrl = new URL(request.url);
      const isPublicFeed = request.method === "GET" && requestUrl.pathname === "/v1/feed" &&
        requestUrl.searchParams.get("scope") !== "following" && !request.headers.get("Authorization");
      const isPublicNews = request.method === "GET" && requestUrl.pathname === "/v1/news" &&
        !request.headers.get("Authorization");
      const cacheable = isPublicFeed || isPublicNews;
      const cacheKey = cacheable ? new Request(requestUrl.toString(), { method: "GET" }) : null;
      if (cacheable) {
        const cached = await caches.default.match(cacheKey);
        if (cached) {
          const cachedHeaders = new Headers(cached.headers);
          cachedHeaders.set("x-gomogie-edge-cache", "HIT");
          for (const [key, value] of Object.entries(headers)) cachedHeaders.set(key, value);
          cachedHeaders.set("x-content-type-options", "nosniff");
          cachedHeaders.set("referrer-policy", "no-referrer");
          cachedHeaders.set("x-frame-options", "DENY");
          cachedHeaders.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
          return new Response(cached.body, { status: cached.status, statusText: cached.statusText, headers: cachedHeaders });
        }
      }
      const response = await route(request, env);
      if (cacheable && response.ok) {
        const cacheHeaders = new Headers(response.headers);
        cacheHeaders.set("cache-control", isPublicFeed ? "public, max-age=30" : "public, max-age=120");
        const cacheResponse = new Response(response.clone().body, {
          status: response.status, statusText: response.statusText, headers: cacheHeaders
        });
        await caches.default.put(cacheKey, cacheResponse);
      }
      const resultHeaders = new Headers(response.headers);
      if (cacheable) resultHeaders.set("x-gomogie-edge-cache", "MISS");
      for (const [key, value] of Object.entries(headers)) resultHeaders.set(key, value);
      resultHeaders.set("x-content-type-options", "nosniff");
      resultHeaders.set("referrer-policy", "no-referrer");
      resultHeaders.set("x-frame-options", "DENY");
      resultHeaders.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers: resultHeaders });
    } catch (error) {
      console.error("GomoGie API error", error);
      const detail = String(error?.message || "");
      if (/D1's free tier daily row read limit/i.test(detail)) {
        return json({ error: "d1_daily_read_limit", message: "Had bacaan harian D1 pelan percuma telah dicapai. Data tidak dipadam; kandungan akan pulih selepas had ditetapkan semula pada 00:00 UTC." }, 503, {
          "retry-after": "3600"
        });
      }
      if (/D1's free tier daily row write limit/i.test(detail)) {
        return json({ error: "d1_daily_write_limit", message: "Had penulisan harian D1 pelan percuma telah dicapai. Data tidak dipadam; fungsi tulis akan pulih selepas had ditetapkan semula pada 00:00 UTC." }, 503, {
          "retry-after": "3600"
        });
      }
      return json({ error: "internal_error", message: "Ralat pelayan. Cuba lagi." }, 500, {
        ...headers,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "x-frame-options": "DENY"
      });
    }
  }
};

// Saved posts are account-scoped in D1; no browser-local persistence is used.
