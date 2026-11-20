/*!
 * s3.js — Client kết nối MinIO / Amazon S3 thuần Node.js (zero-dependency).
 *
 * Sử dụng thuật toán ký chuẩn AWS Signature Version 4 (AWS4-HMAC-SHA256)
 * dựa trên hai hàm mật mã cốt lõi của dự án:
 *   1. SHA-256      : băm nội dung gói tin (x-amz-content-sha256) và Canonical Request
 *   2. HMAC-SHA256  : dẫn xuất chuỗi khoá ký 4 bước (Date -> Region -> Service -> Signing)
 *
 * Cấu hình mặc định khớp với docker-compose.yml:
 *   - Endpoint   : http://127.0.0.1:9000
 *   - Bucket     : zk-vault
 *   - Access Key : minioadmin
 *   - Secret Key : minioadmin
 */
'use strict';

const crypto = require('node:crypto');

const DEFAULTS = {
    endpoint: process.env.S3_ENDPOINT || 'http://127.0.0.1:9000',
    bucket: process.env.S3_BUCKET || 'zk-vault',
    region: process.env.S3_REGION || 'us-east-1',
    accessKey: process.env.S3_ACCESS_KEY || process.env.MINIO_ROOT_USER || 'minioadmin',
    secretKey: process.env.S3_SECRET_KEY || process.env.MINIO_ROOT_PASSWORD || 'minioadmin'
};

function sha256Hex(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function hmac(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest();
}

function hmacHex(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function toAmzDate(date = new Date()) {
    return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function encodeUriPath(pathname) {
    return pathname
        .split('/')
        .map((segment) => encodeURIComponent(segment).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()))
        .join('/');
}

/**
 * Tạo client S3 / MinIO dùng AWS Signature v4.
 */
function createS3Client(options = {}) {
    const cfg = { ...DEFAULTS, ...options };
    const baseUrl = new URL(cfg.endpoint);

    function signRequest(method, objectKey, bodyBuffer = Buffer.alloc(0), nowDate = new Date()) {
        const amzDate = toAmzDate(nowDate);
        const dateStamp = amzDate.slice(0, 8);

        const rawPath = objectKey
            ? `/${cfg.bucket}/${objectKey}`
            : `/${cfg.bucket}`;
        const canonicalUri = encodeUriPath(rawPath);
        const payloadHash = sha256Hex(bodyBuffer);
        const hostHeader = baseUrl.host;

        const canonicalHeaders =
            `host:${hostHeader}\n` +
            `x-amz-content-sha256:${payloadHash}\n` +
            `x-amz-date:${amzDate}\n`;

        const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

        const canonicalRequest = [
            method.toUpperCase(),
            canonicalUri,
            '', // query string
            canonicalHeaders,
            signedHeaders,
            payloadHash
        ].join('\n');

        const credentialScope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
        const stringToSign = [
            'AWS4-HMAC-SHA256',
            amzDate,
            credentialScope,
            sha256Hex(canonicalRequest)
        ].join('\n');

        // Dẫn xuất khoá ký 4 bậc bằng HMAC-SHA256
        const kDate = hmac('AWS4' + cfg.secretKey, dateStamp);
        const kRegion = hmac(kDate, cfg.region);
        const kService = hmac(kRegion, 's3');
        const kSigning = hmac(kService, 'aws4_request');
        const signature = hmacHex(kSigning, stringToSign);

        const authorization =
            `AWS4-HMAC-SHA256 Credential=${cfg.accessKey}/${credentialScope}, ` +
            `SignedHeaders=${signedHeaders}, Signature=${signature}`;

        const url = new URL(canonicalUri, baseUrl).toString();
        const headers = {
            'Authorization': authorization,
            'x-amz-date': amzDate,
            'x-amz-content-sha256': payloadHash
        };

        if (bodyBuffer.length > 0) {
            headers['Content-Type'] = 'application/octet-stream';
            headers['Content-Length'] = String(bodyBuffer.length);
        }

        return { url, headers };
    }

    /** Kiểm tra và tự động tạo bucket trên MinIO nếu chưa tồn tại. */
    async function ensureBucket() {
        const headReq = signRequest('HEAD', '');
        const headRes = await fetch(headReq.url, { method: 'HEAD', headers: headReq.headers });
        if (headRes.status === 200) return true;

        if (headRes.status === 404) {
            const putReq = signRequest('PUT', '');
            const putRes = await fetch(putReq.url, { method: 'PUT', headers: putReq.headers });
            if (putRes.status === 200 || putRes.status === 409) return true;
            throw new Error(`Không thể tạo bucket "${cfg.bucket}" trên MinIO (HTTP ${putRes.status}).`);
        }

        throw new Error(`MinIO trả mã lỗi HTTP ${headRes.status} khi kiểm tra bucket "${cfg.bucket}".`);
    }

    /** Đẩy bản mã (Buffer/Uint8Array) lên MinIO theo objectKey. */
    async function putObject(objectKey, data) {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        const req = signRequest('PUT', objectKey, buf);
        const res = await fetch(req.url, {
            method: 'PUT',
            headers: req.headers,
            body: buf
        });
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            throw new Error(`MinIO PUT thất bại (HTTP ${res.status}): ${text.slice(0, 200)}`);
        }
        return true;
    }

    /** Tải bản mã từ MinIO về dạng Buffer (trả về null nếu không tồn tại). */
    async function getObject(objectKey) {
        const req = signRequest('GET', objectKey);
        const res = await fetch(req.url, {
            method: 'GET',
            headers: req.headers
        });
        if (res.status === 404) return null;
        if (!res.ok) {
            throw new Error(`MinIO GET thất bại (HTTP ${res.status}).`);
        }
        return Buffer.from(await res.arrayBuffer());
    }

    /** Xoá bản mã khỏi MinIO. */
    async function deleteObject(objectKey) {
        const req = signRequest('DELETE', objectKey);
        const res = await fetch(req.url, {
            method: 'DELETE',
            headers: req.headers
        });
        if (res.status === 204 || res.status === 200 || res.status === 404) return true;
        throw new Error(`MinIO DELETE thất bại (HTTP ${res.status}).`);
    }

    return {
        cfg,
        signRequest,
        ensureBucket,
        putObject,
        getObject,
        deleteObject
    };
}

module.exports = { createS3Client, DEFAULTS };
