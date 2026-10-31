"use strict";


/*
 * BDMV WEB HOST
 *
 * Browser-safe functional port.
 *
 * It can load, inspect, verify, download, cache,
 * and play the supplied resources.
 *
 * It cannot execute native PS4 code from inside
 * a normal browser sandbox.
 */


const PAYLOADS =
    BDMV_ASSETS.payloads;


const fileContainer =
    document.getElementById("files");

const fileCount =
    document.getElementById("fileCount");

const viewer =
    document.getElementById("viewer");

const viewerTitle =
    document.getElementById("viewerTitle");

const viewerContent =
    document.getElementById("viewerContent");

const statusElement =
    document.getElementById("status");


let activeRun = 0;
let activeController = null;


/*
 * INITIALIZE
 */

renderPayloadButtons();
registerServiceWorker();




/*
 * PAYLOAD BUTTONS
 */

function renderPayloadButtons() {

    fileCount.textContent =
        PAYLOADS.length + " ITEMS";


    PAYLOADS.forEach(function(item) {

        const button =
            document.createElement("button");

        button.type = "button";
        button.className = "item";


        const filename =
            item.path.split("/").pop();


        button.innerHTML = `

            <div class="item-icon">
                ▣
            </div>

            <div class="item-text">

                <strong>
                    ${escapeHTML(filename)}
                </strong>

                <span>
                    ${escapeHTML(item.path)}
                    &nbsp;•&nbsp;
                    ${escapeHTML(formatBytes(item.bytes))}
                </span>

            </div>

        `;


        button.addEventListener(
            "click",
            function() {
                loadResource(item.path);
            }
        );


        fileContainer.appendChild(button);

    });

}




/*
 * START BROWSER-SAFE ISO WORKFLOW
 */

async function startIsoWorkflow() {

    const run = ++activeRun;

    if (activeController) {
        activeController.abort();
    }

    const controller =
        new AbortController();

    activeController = controller;


    viewerTitle.textContent =
        "BROWSER WORKFLOW";


    viewerContent.innerHTML = `

        <video
            controls
            autoplay
            preload="metadata"
            src="assets/00000.mp4"
        ></video>


        <div class="note">
            Loading and validating all supplied resources.
        </div>


        <div class="meter">
            <div
                id="workflowProgress"
                class="meter-fill"
            ></div>
        </div>


        <div
            id="workflowProgressLabel"
            class="progress-label"
        >
            0 / ${PAYLOADS.length}
        </div>


        <div
            id="workflowLog"
            class="terminal"
        ></div>

    `;


    showViewer();
    setStatus("RUNNING");


    const video =
        viewerContent.querySelector("video");


    if (video) {

        video.addEventListener(
            "error",
            function() {
                appendLog(
                    "workflowLog",
                    "WARNING: Browser could not decode 00000.mp4.",
                    "warn"
                );
            }
        );


        try {
            await video.play();
        } catch (error) {
            appendLog(
                "workflowLog",
                "Video autoplay was blocked or delayed; press Play manually.",
                "warn"
            );
        }

    }


    appendLog(
        "workflowLog",
        "Starting browser-safe BDMV workflow.",
        "ok"
    );


    const verified =
        await verifyPayloadCollection(
            "workflowLog",
            "workflowProgress",
            "workflowProgressLabel",
            run,
            controller.signal
        );


    if (run !== activeRun) {
        return;
    }


    if (!verified) {
        setStatus("ERROR");
        return;
    }


    appendLog(
        "workflowLog",
        "Media and payload resources loaded successfully.",
        "ok"
    );


    appendLog(
        "workflowLog",
        "Browser sandbox reached. Native hen.bin execution is unavailable.",
        "warn"
    );


    appendLog(
        "workflowLog",
        "BD-J and PS4 privileged operations require the original Xlet code and console APIs.",
        "warn"
    );


    appendLog(
        "workflowLog",
        "Browser workflow completed.",
        "ok"
    );


    setStatus("READY");

}




/*
 * PLAY MP4 VIDEO
 */

function loadVideo() {

    viewerTitle.textContent =
        "00000.MP4";


    viewerContent.innerHTML = `

        <video
            controls
            autoplay
            preload="metadata"
            src="assets/00000.mp4"
        ></video>

        <div class="download-row">

            <a
                class="download"
                href="assets/00000.mp4"
                download
            >
                DOWNLOAD MP4
            </a>

        </div>

    `;


    showViewer();
    setStatus("MEDIA READY");

}




/*
 * ORIGINAL M2TS STREAM
 */

function loadStream() {

    viewerTitle.textContent =
        "00000.M2TS";


    viewerContent.innerHTML = `

        <p>
            Original MPEG transport stream from the ISO.
        </p>

        <p class="note">
            Most browsers cannot play M2TS directly, so this action
            provides the original file for download.
        </p>

        <div class="download-row">

            <a
                class="download"
                href="assets/00000.m2ts"
                download
            >
                DOWNLOAD ORIGINAL STREAM
            </a>

        </div>

    `;


    showViewer();
    setStatus("STREAM READY");

}




/*
 * LOAD INDIVIDUAL RESOURCE
 */

async function loadResource(path) {

    const item =
        PAYLOADS.find(function(entry) {
            return entry.path === path;
        });


    viewerTitle.textContent =
        path.split("/").pop().toUpperCase();


    viewerContent.innerHTML = `

        <p id="resourceProgress">
            Loading resource...
        </p>

    `;


    showViewer();
    setStatus("LOADING");


    try {

        const progressElement =
            document.getElementById(
                "resourceProgress"
            );


        const bytes =
            await fetchAsset(
                path,
                null,
                function(loaded, total) {

                    if (!progressElement) {
                        return;
                    }


                    if (total > 0) {

                        const percent =
                            Math.round(
                                loaded / total * 100
                            );

                        progressElement.textContent =
                            "Loading resource... " +
                            percent +
                            "%";

                    } else {

                        progressElement.textContent =
                            "Loading resource... " +
                            formatBytes(loaded);

                    }

                }
            );


        const hash =
            await sha256Hex(bytes.buffer);


        const expectedSize =
            item ? item.bytes : null;


        const sizeMatches =
            expectedSize === null ||
            bytes.length === expectedSize;


        viewerContent.innerHTML = `

            <div class="file-info">

                <strong>
                    ${escapeHTML(path)}
                </strong>

                <br><br>

                Size:
                ${bytes.length.toLocaleString()}
                bytes

                ${
                    expectedSize !== null
                        ? "<br>Expected: " +
                          expectedSize.toLocaleString() +
                          " bytes"
                        : ""
                }

                <br>
                Size check:
                ${
                    sizeMatches
                        ? '<span class="success">PASS</span>'
                        : '<span class="danger">FAIL</span>'
                }

                <br>
                SHA-256:
                <span class="hash">
                    ${escapeHTML(hash)}
                </span>

            </div>


            <div class="download-row">

                <a
                    class="download"
                    href="assets/${encodeURI(path)}"
                    download
                >
                    DOWNLOAD RESOURCE
                </a>

            </div>


            <h3>Binary preview</h3>

            <pre class="terminal">${
                escapeHTML(hexDump(bytes, 256))
            }</pre>

        `;


        setStatus(
            sizeMatches
                ? "LOADED"
                : "SIZE MISMATCH"
        );

    } catch (error) {

        viewerContent.innerHTML = `

            <p>
                Failed to load resource.
            </p>

            <div class="file-info danger">
                ${escapeHTML(error.message)}
            </div>

        `;


        setStatus("ERROR");

    }

}




/*
 * VERIFY ALL PAYLOAD FILES
 */

async function verifyAll() {

    const run = ++activeRun;

    if (activeController) {
        activeController.abort();
    }

    const controller =
        new AbortController();

    activeController = controller;


    viewerTitle.textContent =
        "PAYLOAD VERIFICATION";


    viewerContent.innerHTML = `

        <p class="note">
            Verifying all expected payload and template resources.
        </p>


        <div class="meter">
            <div
                id="verifyProgress"
                class="meter-fill"
            ></div>
        </div>


        <div
            id="verifyProgressLabel"
            class="progress-label"
        >
            0 / ${PAYLOADS.length}
        </div>


        <div
            id="verifyLog"
            class="terminal"
        ></div>

    `;


    showViewer();
    setStatus("VERIFYING");


    const verified =
        await verifyPayloadCollection(
            "verifyLog",
            "verifyProgress",
            "verifyProgressLabel",
            run,
            controller.signal
        );


    if (run !== activeRun) {
        return;
    }


    setStatus(
        verified
            ? "VERIFIED"
            : "ERROR"
    );

}




/*
 * SHARED PAYLOAD VERIFICATION ROUTINE
 */

async function verifyPayloadCollection(
    logId,
    progressId,
    progressLabelId,
    run,
    signal
) {

    let completed = 0;


    appendLog(
        logId,
        "Verification started.",
        "ok"
    );


    for (
        let index = 0;
        index < PAYLOADS.length;
        index++
    ) {

        if (
            run !== activeRun ||
            signal.aborted
        ) {
            return false;
        }


        const item =
            PAYLOADS[index];


        appendLog(
            logId,
            "LOAD " + item.path
        );


        try {

            const bytes =
                await fetchAsset(
                    item.path,
                    signal,
                    function(loaded, total) {

                        let message =
                            "  " +
                            formatBytes(loaded);


                        if (total > 0) {

                            message +=
                                " / " +
                                formatBytes(total);

                        }


                        appendTemporaryLog(
                            logId,
                            message
                        );

                    }
                );


            if (bytes.length !== item.bytes) {

                throw new Error(
                    "expected " +
                    item.bytes +
                    " bytes, received " +
                    bytes.length +
                    " bytes"
                );

            }


            const hash =
                await sha256Hex(bytes.buffer);


            appendLog(
                logId,
                "OK   " +
                item.path +
                " — " +
                bytes.length.toLocaleString() +
                " bytes — " +
                hash,
                "ok"
            );


        } catch (error) {

            if (
                run !== activeRun ||
                signal.aborted
            ) {
                return false;
            }


            appendLog(
                logId,
                "FAIL " +
                item.path +
                " — " +
                error.message,
                "bad"
            );


            appendLog(
                logId,
                "Verification failed.",
                "bad"
            );


            return false;

        }


        completed++;


        setProgress(
            progressId,
            completed,
            PAYLOADS.length
        );


        const progressLabel =
            document.getElementById(
                progressLabelId
            );


        if (progressLabel) {

            progressLabel.textContent =
                completed +
                " / " +
                PAYLOADS.length;

        }

    }


    if (
        run !== activeRun ||
        signal.aborted
    ) {
        return false;
    }


    appendLog(
        logId,
        "PASS — " +
        PAYLOADS.length +
        " resources validated.",
        "ok"
    );


    return true;

}




/*
 * FETCH ASSET WITH PROGRESS
 */

async function fetchAsset(
    path,
    signal,
    onProgress
) {

    const response =
        await fetch(
            "assets/" + path,
            {
                signal: signal || undefined,
                cache: "no-store"
            }
        );


    if (!response.ok) {

        throw new Error(
            response.status +
            " " +
            response.statusText
        );

    }


    const total =
        Number(
            response.headers.get(
                "content-length"
            )
        ) || 0;


    if (
        !response.body ||
        !response.body.getReader
    ) {

        const buffer =
            await response.arrayBuffer();


        if (onProgress) {

            onProgress(
                buffer.byteLength,
                total || buffer.byteLength
            );

        }


        return new Uint8Array(buffer);

    }


    const reader =
        response.body.getReader();


    const chunks = [];


    let received = 0;


    while (true) {

        const result =
            await reader.read();


        if (result.done) {
            break;
        }


        chunks.push(result.value);


        received +=
            result.value.length;


        if (onProgress) {

            onProgress(
                received,
                total
            );

        }

    }


    const bytes =
        new Uint8Array(received);


    let offset = 0;


    chunks.forEach(function(chunk) {

        bytes.set(
            chunk,
            offset
        );


        offset +=
            chunk.length;

    });


    return bytes;

}




/*
 * HASHING
 */

async function sha256Hex(buffer) {

    try {

        if (
            !globalThis.crypto ||
            !globalThis.crypto.subtle
        ) {
            throw new Error(
                "Web Crypto unavailable"
            );
        }


        const digest =
            await globalThis.crypto.subtle.digest(
                "SHA-256",
                buffer
            );


        return Array.from(
            new Uint8Array(digest)
        )
        .map(function(byte) {
            return byte
                .toString(16)
                .padStart(2, "0");
        })
        .join("");


    } catch (error) {

        return (
            "Unavailable — use HTTPS " +
            "or http://localhost"
        );

    }

}




/*
 * HEX PREVIEW
 */

function hexDump(bytes, maximum) {

    const limit =
        Math.min(
            bytes.length,
            maximum || 256
        );


    const lines = [];


    for (
        let offset = 0;
        offset < limit;
        offset += 16
    ) {

        const end =
            Math.min(
                offset + 16,
                limit
            );


        const slice =
            bytes.subarray(
                offset,
                end
            );


        const hex =
            Array.from(slice)
            .map(function(byte) {
                return byte
                    .toString(16)
                    .padStart(2, "0");
            })
            .join(" ")
            .padEnd(47);


        const text =
            Array.from(slice)
            .map(function(byte) {

                if (
                    byte >= 32 &&
                    byte <= 126
                ) {
                    return String.fromCharCode(byte);
                }


                return ".";

            })
            .join("");


        lines.push(
            offset
                .toString(16)
                .padStart(8, "0") +

            "  " +
            hex +
            "  |" +
            text +
            "|"
        );

    }


    if (bytes.length > limit) {

        lines.push(
            "… " +
            (bytes.length - limit).toLocaleString() +
            " more bytes"
        );

    }


    return lines.join("\n");

}




/*
 * PROGRESS
 */

function setProgress(
    elementId,
    completed,
    total
) {

    const element =
        document.getElementById(elementId);


    if (!element) {
        return;
    }


    const percent =
        total > 0
            ? completed / total * 100
            : 0;


    element.style.width =
        percent + "%";

}




/*
 * LOGGING
 */

function appendLog(
    logId,
    message,
    type
) {

    const log =
        document.getElementById(logId);


    if (!log) {
        return;
    }


    const temporary =
        log.querySelector(
            ".temporary-log"
        );


    if (temporary) {
        temporary.remove();
    }


    const line =
        document.createElement("div");


    line.className =
        "log-line " +
        (type || "");


    line.textContent =
        message;


    log.appendChild(line);


    log.scrollTop =
        log.scrollHeight;

}




/*
 * Temporary transfer-progress line.
 */

function appendTemporaryLog(
    logId,
    message
) {

    const log =
        document.getElementById(logId);


    if (!log) {
        return;
    }


    let line =
        log.querySelector(
            ".temporary-log"
        );


    if (!line) {

        line =
            document.createElement("div");


        line.className =
            "log-line temporary-log";


        log.appendChild(line);

    }


    line.textContent =
        message;


    log.scrollTop =
        log.scrollHeight;

}




/*
 * VIEWER
 */

function showViewer() {

    viewer.classList.remove(
        "hidden"
    );


    viewer.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });

}




/*
 * CLOSE VIEWER
 */

function closeViewer() {

    activeRun++;


    if (activeController) {

        activeController.abort();

        activeController = null;

    }


    viewer.classList.add(
        "hidden"
    );


    viewerContent.innerHTML =
        "";


    setStatus("READY");

}




/*
 * STATUS
 */

function setStatus(value) {

    statusElement.textContent =
        value;

}




/*
 * SERVICE WORKER
 */

function registerServiceWorker() {

    if (
        !("serviceWorker" in navigator) ||
        !/^https?:$/.test(location.protocol)
    ) {
        return;
    }


    navigator.serviceWorker
        .register("./sw.js")
        .catch(function() {
            // The application still works without offline caching.
        });

}




/*
 * FORMAT BYTES
 */

function formatBytes(bytes) {

    if (
        bytes === null ||
        bytes === undefined ||
        isNaN(bytes)
    ) {
        return "Unknown";
    }


    if (bytes < 1024) {
        return bytes + " B";
    }


    if (bytes < 1024 * 1024) {
        return (
            (bytes / 1024).toFixed(1) +
            " KB"
        );
    }


    return (
        (bytes / (1024 * 1024)).toFixed(2) +
        " MB"
    );

}




/*
 * HTML ESCAPING
 */

function escapeHTML(value) {

    const entities = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;"
    };


    return String(value).replace(
        /[&<>"']/g,
        function(character) {
            return entities[character];
        }
    );

}