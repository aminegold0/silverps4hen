"use strict";

importScripts("./asset-list.js");


const CACHE_NAME =
    "bdmv-web-v3";


const CORE_ASSETS = [

    "./",
    "./index.html",
    "./style.css",
    "./asset-list.js",
    "./app.js"

];


const MEDIA_ASSETS =
    BDMV_ASSETS.media.map(function(item) {
        return "./assets/" + item.path;
    });


const PAYLOAD_ASSETS =
    BDMV_ASSETS.payloads.map(function(item) {
        return "./assets/" + item.path;
    });


const ALL_ASSETS =
    CORE_ASSETS
        .concat(MEDIA_ASSETS)
        .concat(PAYLOAD_ASSETS);


self.addEventListener(
    "install",
    function(event) {

        event.waitUntil(

            caches
                .open(CACHE_NAME)
                .then(function(cache) {
                    return cache.addAll(ALL_ASSETS);
                })
                .then(function() {
                    return self.skipWaiting();
                })

        );

    }
);


self.addEventListener(
    "activate",
    function(event) {

        event.waitUntil(
            self.clients.claim()
        );

    }
);


self.addEventListener(
    "fetch",
    function(event) {

        if (
            event.request.method !== "GET"
        ) {
            return;
        }


        const requestURL =
            new URL(event.request.url);


        if (
            requestURL.origin !==
            self.location.origin
        ) {
            return;
        }


        event.respondWith(

            caches
                .match(event.request)
                .then(function(cached) {

                    if (cached) {
                        return cached;
                    }


                    return fetch(event.request)
                        .then(function(response) {

                            if (!response.ok) {
                                return response;
                            }


                            const copy =
                                response.clone();


                            caches
                                .open(CACHE_NAME)
                                .then(function(cache) {
                                    cache.put(
                                        event.request,
                                        copy
                                    );
                                });


                            return response;

                        });

                })

        );

    }
);