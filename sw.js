const CACHE_PREFIX="gomogie-shell-";
const CACHE_NAME=CACHE_PREFIX+"v28";
const APP_SHELL=["./","./index.html","./manifest.webmanifest","./assets/brand/favicon.svg","./assets/brand/apple-touch-icon.png","./assets/brand/icon-192.png","./assets/brand/icon-512.png","./assets/brand/GomoGie-wordmark-transparent.svg","./assets/brand/brand-tokens.css","./data/demo-accounts.json","./data/demo-posts.json"];
const scopedURL=path=>new URL(path,self.registration.scope).href;
const normalizedDataURL=value=>{const clean=new URL(value);clean.search="";clean.hash="";return clean.href};
self.addEventListener("install",event=>{event.waitUntil((async()=>{const cache=await caches.open(CACHE_NAME);await cache.addAll(APP_SHELL.map(scopedURL));await self.skipWaiting()})())});
self.addEventListener("activate",event=>{event.waitUntil((async()=>{const keys=await caches.keys();await Promise.all(keys.filter(key=>key.startsWith(CACHE_PREFIX)&&key!==CACHE_NAME).map(key=>caches.delete(key)));await self.clients.claim()})())});
self.addEventListener("fetch",event=>{
 const request=event.request,url=new URL(request.url);
 if(request.method!=="GET"||url.origin!==self.location.origin)return;
 if(url.pathname.includes("/data/")){
  event.respondWith((async()=>{const cache=await caches.open(CACHE_NAME),key=normalizedDataURL(url.href);try{const fresh=await fetch(request,{cache:"no-store"});if(fresh.ok)await cache.put(key,fresh.clone());return fresh}catch(error){return (await cache.match(key))||Response.error()}})());return;
 }
 if(request.mode==="navigate"||request.destination==="document"){
  event.respondWith((async()=>{try{const fresh=await fetch(request,{cache:"no-store"});if(fresh.ok){const cache=await caches.open(CACHE_NAME);await cache.put(scopedURL("./index.html"),fresh.clone())}return fresh}catch(error){return (await caches.match(request))||(await caches.match(scopedURL("./index.html")))||Response.error()}})());return;
 }
 if(["style","script","image","font"].includes(request.destination)){
  event.respondWith((async()=>{const cache=await caches.open(CACHE_NAME);try{const fresh=await fetch(request,{cache:"no-store"});if(fresh.ok)await cache.put(request,fresh.clone());return fresh}catch(error){return (await cache.match(request))||Response.error()}})())
 }
});
