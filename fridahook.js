'use strict';

// Global containers
const hostMap = {};              // Stores resolved hostnames
const accumulators = {};         // Buffers per SSL connection, used to reconstruct JSON payloads

// Utility function: convert bytes to ASCII (with optional truncation)
function bytesToAscii(byteArray, maxLen) {
    const n = Math.min(byteArray.length, maxLen);
    let s = "";
    for (let i = 0; i < n; i++) s += String.fromCharCode(byteArray[i]);
    return s;
}

// Remember a hostname for later correlation (e.g., when Host header is missing)
function rememberHost(h) { if (h) hostMap[h] = true; }

// Hook getaddrinfo to capture DNS resolution requests
try {
    const gai = Module.findExportByName("libc.so", "getaddrinfo");
    if (gai) {
        Interceptor.attach(gai, {
            onEnter(args) {
                try {
                    const nodePtr = args[0];
                    if (!nodePtr) return;
                    const host = Memory.readUtf8String(nodePtr);
                    if (!host) return;
                    console.log("[DNS] Resolving host: " + host);
                    rememberHost(host);
                } catch (e) {
                    console.warn("[DNS] read error: " + e);
                }
            }
        });
        console.log("[DNS] getaddrinfo hooked successfully");
    } else {
        console.warn("[DNS] getaddrinfo not found");
    }
} catch (e) {
    console.warn("[DNS] hook error: " + e);
}

// Function to attach to SSL_write or SSL_write_ex
function attachSSLWrite(funcName) {
    try {
        const addr = Module.findExportByName(null, funcName);
        if (!addr) { 
            console.warn("[SSL] " + funcName + " not found"); 
            return false; 
        }
        console.log("[SSL] Hooking " + funcName);
        Interceptor.attach(addr, {
            onEnter(args) {
                try {
                    const ssl = args[0];
                    const buf = args[1];
                    const len = args[2].toInt32 ? args[2].toInt32() : Number(args[2]);
                    if (!buf || !ssl || !len || len <= 0) return;

                    const dataBytes = Memory.readByteArray(buf, len);
                    if (!dataBytes) return;

                    // Print a short preview of the outgoing data
                    const asciiChunk = bytesToAscii(new Uint8Array(dataBytes), 4096);
                    console.log("[SSL] chunk length=" + len + " preview=" + asciiChunk.substring(0, 256));

                    // Store into accumulator for this SSL connection
                    const sslKey = ssl.toString();
                    accumulators[sslKey] = (accumulators[sslKey] || "") + asciiChunk;

                    // Try to extract JSON body from accumulated data
                    const fullData = accumulators[sslKey];
                    const startIndex = fullData.indexOf('{');
                    if (startIndex !== -1) {
                        let brace = 0, inStr = false, esc = false, endIndex = -1;
                        for (let i = startIndex; i < fullData.length; i++) {
                            const ch = fullData[i];
                            if (!inStr) {
                                if (ch === '{') brace++;
                                else if (ch === '}') {
                                    brace--;
                                    if (brace === 0) { endIndex = i; break; }
                                } else if (ch === '"') inStr = true;
                            } else {
                                if (ch === '"' && !esc) inStr = false;
                                esc = (ch === '\\') && !esc;
                            }
                        }
                        if (endIndex !== -1) {
                            const jsonStr = fullData.substring(startIndex, endIndex + 1);
                            try {
                                const obj = JSON.parse(jsonStr);
                                let promptText = null;
                                if (obj && obj.contents && obj.contents[0] && obj.contents[0].parts && obj.contents[0].parts[0]) {
                                    promptText = obj.contents[0].parts[0].text || null;
                                }

                                // Try to derive API endpoint (from HTTP/1.1 headers or hostMap)
                                let apiUrl = "Unknown API URL";
                                const http11Idx = fullData.indexOf(" HTTP/1.1");
                                if (http11Idx !== -1) {
                                    const methodIdx = fullData.lastIndexOf("POST ", http11Idx);
                                    if (methodIdx !== -1) {
                                        const path = fullData.substring(methodIdx + 5, http11Idx);
                                        const hostIdx = fullData.indexOf("Host:");
                                        if (hostIdx !== -1) {
                                            const hostStart = hostIdx + 5;
                                            const hostEnd = fullData.indexOf("\r\n", hostStart);
                                            const hostName = fullData.substring(hostStart, hostEnd).trim();
                                            apiUrl = "https://" + hostName + path;
                                            rememberHost(hostName);
                                        } else {
                                            apiUrl = path;
                                        }
                                    }
                                } else {
                                    // Likely HTTP/2 or gRPC
                                    const hosts = Object.keys(hostMap);
                                    if (hosts.length > 0) apiUrl = "https://" + hosts[0] + "/(HTTP/2 or gRPC)";
                                }

                                // Print the extracted information
                                console.log("[SSL] User prompt: " + (promptText !== null ? promptText : "(not found)"));
                                console.log("[SSL] API URL: " + apiUrl);
                                console.log("[SSL] JSON body length: " + jsonStr.length);

                            } catch (err) {
                                console.warn("[SSL] JSON parse error: " + err);
                            }
                            // Clear accumulator to avoid re-parsing the same data
                            accumulators[sslKey] = "";
                        }
                    }
                } catch (e) {
                    console.warn("[SSL] onEnter error: " + e);
                }
            }
        });
        return true;
    } catch (e) {
        console.warn("[SSL] attach error: " + e);
        return false;
    }
}

// Try both SSL_write and SSL_write_ex
const ok1 = attachSSLWrite("SSL_write");
const ok2 = ok1 ? true : attachSSLWrite("SSL_write_ex");
console.log("[SSL] attach result SSL_write=" + ok1 + " SSL_write_ex=" + ok2);
