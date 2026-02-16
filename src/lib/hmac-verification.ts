import * as crypto from 'node:crypto';

function recursivelySortKeys(value: unknown): unknown {
    if (value === null || typeof value !== 'object') {
        return value;
    }
    if (Array.isArray(value)) {
        return value.map(recursivelySortKeys);
    }
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as object).sort()) {
        sorted[key] = recursivelySortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
}

export function verifyHmacSignature(payload: unknown, headerValue: string, apiToken: string, webhookUrl: string, maxAgeSeconds = 300) {
    // Parse the header value: signature,timestamp,nonce
    const parts = headerValue.split(',');
    if (parts.length !== 3) {
        throw new Error('Invalid header format');
    }

    const [signaturePart, timestampStr, nonce] = parts;
    if(!signaturePart || !timestampStr || !nonce){
        throw new Error('Invalid header format');
    }

    // Validate timestamp to prevent replay attacks
    const timestamp = parseInt(timestampStr, 10);
    const currentTime = Math.floor(Date.now() / 1000);
    if (Math.abs(currentTime - timestamp) > maxAgeSeconds) {
        throw new Error('Signature timestamp is too old');
    }

    // Parse the signature to extract algorithm and value
    if (!signaturePart.includes('=')) {
        throw new Error('Invalid signature format');
    }

    const [algorithm, signatureValue] = signaturePart.split('=', 2);
    if(!algorithm || !signatureValue){
        throw new Error('Invalid signature format');
    }

    const sortedPayload = recursivelySortKeys(payload);

    // JSON encode the sorted payload
    const jsonPayload = JSON.stringify(sortedPayload);

    // Combine URL and payload as done in signature generation
    const signatureData = webhookUrl + '|' + jsonPayload;

    // Compute expected signature
    const expectedSignature = crypto
        .createHmac(algorithm, apiToken)
        .update(signatureData, 'utf8')
        .digest('hex');

    // Compare signatures using timing-safe comparison
    return crypto.timingSafeEqual(
        Buffer.from(expectedSignature, 'hex'),
        Buffer.from(signatureValue, 'hex')
    );
}
