/**
 * Webhook callback endpoint
 * Accepts arbitrary body and headers for webhook processing
 */
import {verifyHmacSignature} from "./lib/hmac-verification.ts";

const SIGNATURE_HEADER_KEY = Bun.env.SIGNATURE_HEADER_KEY;
const API_TOKEN = Bun.env.API_TOKEN;
const WEBHOOK_URL = Bun.env.WEBHOOK_URL;


const server = Bun.serve({
    port: process.env.PORT || 3000,
    async fetch(req) {
        const url = new URL(req.url);

        // Handle webhook endpoint
        if (url.pathname === "/webhook" && req.method === "POST") {
            try {
                console.debug("🪝 Webhook received...");
                // Collect all headers
                const headers: Record<string, string> = {};
                req.headers.forEach((value, key) => {
                    headers[key] = value;
                });

                // Read body - handle different content types
                let body: string | ArrayBuffer | Uint8Array;
                const contentType = req.headers.get("content-type") || "";

                if (contentType.includes("application/json") || contentType.includes("text/")) {
                    body = await req.text();
                } else {
                    throw new Error("Unsupported content type");
                }


                const payload = JSON.parse(body);

                // Log webhook data (in production, you'd process this)
                console.debug({
                    timestamp: new Date().toISOString(),
                    method: req.method,
                    url: url.href,
                    headers: headers,
                    bodySize: body.length,
                    contentType,
                    bodyString: body,
                    body: JSON.parse(body)
                });

                try {
                    if(!headers[SIGNATURE_HEADER_KEY]) {
                        throw new Error('Invalid header format');
                    }
                    if (verifyHmacSignature(payload, headers[SIGNATURE_HEADER_KEY], API_TOKEN, WEBHOOK_URL)) {
                        console.debug('Signature is valid');
                    } else {
                        console.error('Signature is invalid');
                    }
                } catch (error) {
                    if(error instanceof Error){
                        console.error('Error:', error.message);
                    }
                    else {
                        console.error('Error:', error);
                    }
                }


                // Process webhook here (add your business logic)
                // For now, just return success
                return new Response(
                    JSON.stringify({
                        success: true,
                        message: "Webhook received",
                        timestamp: new Date().toISOString(),
                    }),
                    {
                        status: 200,
                        headers: {
                            "Content-Type": "application/json",
                        },
                    }
                );
            } catch (error) {
                console.error("Error processing webhook:", error);
                return new Response(
                    JSON.stringify({
                        success: false,
                        error: error instanceof Error ? error.message : "Unknown error",
                    }),
                    {
                        status: 500,
                        headers: {
                            "Content-Type": "application/json",
                        },
                    }
                );
            }
        }

        // Health check endpoint
        if (url.pathname === "/health") {
            return new Response(
                JSON.stringify({
                    status: "ok",
                    timestamp: new Date().toISOString(),
                }),
                {
                    status: 200,
                    headers: {
                        "Content-Type": "application/json",
                    },
                }
            );
        }

        // 404 for other routes
        return new Response("Not Found", {status: 404});
    },
});


console.info(`🚀 Webhook server running on http://localhost:${server.port}`);
console.info(`📡 Webhook endpoint: http://localhost:${server.port}/webhook`);
console.info(`❤️  Health check: http://localhost:${server.port}/health`);