const CACHE_PREFIX="gomogie-shell-";
const CACHE_NAME=CACHE_PREFIX+"v38";
const APP_SHELL=["./","./index.html","./manifest.webmanifest","./assets/brand/favicon.svg","./assets/brand/apple-touch-icon.png","./assets/brand/icon-192.png","./assets/brand/icon-512.png","./assets/brand/GomoGie-wordmark-transparent.svg","./assets/brand/brand-tokens.css","./data/demo-accounts.json","./data/demo-posts.json"];
const scopedURL=path=>new URL(path,self.registration.scope).href;
const normalizedDataURL=value=>{const clean=new URL(value);clean.search="";clean.hash="";return clean.href};
self.addEventListener("install",event=>{event.waitUntil((async()=>{
 const cache=await caches.open(CACHE_NAME);
 await Promise.all(APP_SHELL.map(async path=>{
  const url=scopedURL(path);
  const response=await fetch(new Request(url,{cache:"reload"}));
  if(!response.ok)throw new Error("Unable to refresh app shell: "+path+" ("+response.status+")");
  await cache.put(url,response);
 }));
 await self.skipWaiting();
})())});
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

self.addEventListener("push",event=>{let data={title:"GomoGie",body:"You have a new notification.",url:"./"};try{if(event.data)data={...data,...event.data.json()}}catch{}event.waitUntil(self.registration.showNotification(data.title||"GomoGie",{body:data.body||"You have a new notification.",icon:"./assets/brand/icon-192.png",badge:"./assets/brand/icon-192.png",data:{url:data.url||"./"},tag:data.tag||"gomogie-notification"}))});
self.addEventListener("notificationclick",event=>{event.notification.close();const target=new URL(event.notification.data?.url||"./",self.registration.scope).href;event.waitUntil(self.clients.matchAll({type:"window",includeUncontrolled:true}).then(clients=>{for(const client of clients){if(client.url.startsWith(self.location.origin)&&"focus"in client)return client.focus().then(()=>client.navigate?client.navigate(target):client)}return self.clients.openWindow(target)}))});
