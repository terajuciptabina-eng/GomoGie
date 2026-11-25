const CACHE_PREFIX="gomogie-shell-";
const CACHE_NAME=CACHE_PREFIX+"v22";
const APP_SHELL=["./","./index.html","./manifest.webmanifest","./assets/brand/favicon.svg","./assets/brand/GomoGie-wordmark-transparent.svg","./assets/brand/brand-tokens.css"];
self.addEventListener("install",event=>{
 event.waitUntil((async()=>{
  const cache=await caches.open(CACHE_NAME);
  await cache.addAll(APP_SHELL);
  await self.skipWaiting();
 })());
});
self.addEventListener("activate",event=>{
 event.waitUntil((async()=>{
  const keys=await caches.keys();
  await Promise.all(keys.filter(key=>key.startsWith(CACHE_PREFIX)&&key!==CACHE_NAME).map(key=>caches.delete(key)));
  await self.clients.claim();
 })());
});
self.addEventListener("fetch",event=>{
 const request=event.request;
 const url=new URL(request.url);
 if(request.method!=="GET"||url.origin!==self.location.origin)return;
 if(url.pathname.includes("/data/"))return;
 if(request.mode==="navigate"||request.destination==="document"){
  event.respondWith((async()=>{
   const cache=await caches.open(CACHE_NAME);
   try{
    const fresh=await fetch(request,{cache:"no-store"});
    if(fresh.ok)await cache.put("./index.html",fresh.clone());
    return fresh;
   }catch(error){
    return (await cache.match(request))||(await cache.match("./index.html"))||Response.error();
   }
  })());
  return;
 }
 if(["style","script","image","font"].includes(request.destination)){
  event.respondWith((async()=>{
   const cache=await caches.open(CACHE_NAME);
   try{
    const fresh=await fetch(request);
    if(fresh.ok)await cache.put(request,fresh.clone());
    return fresh;
   }catch(error){
    return (await cache.match(request))||Response.error();
   }
  })());
 }
});
