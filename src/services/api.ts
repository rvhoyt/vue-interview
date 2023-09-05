import { MD5 } from 'crypto-js';
import hmacSHA256 from 'crypto-js/hmac-sha256';

interface ObjectLiteral {
    [key: string]: any;
}

interface ReftabResponse {
    status: number,
    statusText: string,
    data: any,
    headers: Headers
}

interface Request {
    body?: string,
    method: string,
    headers: ObjectLiteral,
    url: string
}

//CryptoJS is needed for the MD5 and HmacSHA256 methods
function signRequest(request: Request, basic = false, skipAuth = false): Promise<Request> {
    return new Promise<Request>(function (resolve) {
        if (skipAuth) {
            resolve(request);
            return;
        }
        if (basic && request.body) {
            const basicBody = JSON.parse(request.body);
            request.headers.Authorization = 'Basic ' +
                btoa(basicBody.username + ':' + basicBody.password);
            request.method = 'GET';
            delete request.body;
            resolve(request);
            return;
        }
        const publicKey = '1';
        const secretKey = '1';
        const body = request.body;
        const method = request.method;
        const url = request.url;
        const now = new Date().toUTCString();
        let contentMD5 = '';
        let contentType = '';
        if (body !== undefined) {
            contentMD5 = MD5(body).toString();
            contentType = 'application/json';
        }
        let signatureToSign = method + '\n' +
            contentMD5 + '\n' +
            contentType + '\n' +
            now + '\n' +
            url;
        signatureToSign = unescape(encodeURIComponent(signatureToSign));
        const token = btoa(hmacSHA256(signatureToSign, secretKey).toString());
        const signature = 'RT ' + publicKey + ':' + token;
        request.headers.Authorization = signature;
        request.headers['x-rt-date'] = now;
        resolve(request);
    });
}

var url = 'https://devrh.reftab.com/api';
async function processData(r: Response) {
    if (r.status === 204) {
        return {
            status: r.status,
            statusText: r.statusText,
            data: {},
            headers: r.headers
        };
    }
    const data = await decodeJson(r);
    const resp = {
        status: r.status,
        statusText: r.statusText,
        data: data,
        headers: r.headers
    };
    if (r.status >= 200 && r.status < 400) {
        return resp;
    }
    throw resp;
}

async function decodeJson(r: Response) {
    const orig = r.clone();
    try {
        return await r.json();
    } catch (e) {
        const errorData = await orig.text();
        console.log('JSON error: ' + e);
        console.log(r.ok);
        console.log(r.status);
        console.log(r.statusText);
        console.log(errorData);
        return {error: errorData};
    }
}

function encodeEnpoints(endpoint: string) {
    var parts = endpoint.split('/');
    parts = parts.map(function (part) {
        if (part.indexOf('?') !== -1) {
            return part;
        }
        return encodeURIComponent(part);
    });
    return '/' + parts.join('/');
}

export default {
    get: function (endpoint: string, auth = false, headers: ObjectLiteral = {}): Promise<ReftabResponse> {
        endpoint = encodeEnpoints(endpoint);
        return signRequest({
            method: 'GET',
            url: url + endpoint,
            headers: headers
        }, false, auth).then(function (request) {
            return fetch(url + endpoint, request).then(processData);
        })
    },
    post: function (endpoint: string, body: ObjectLiteral, basic: boolean = false, headers: ObjectLiteral = { 'Content-Type': 'application/json' }) {
        endpoint = encodeEnpoints(endpoint);
        return signRequest({
            method: 'POST',
            url: url + endpoint,
            headers: headers,
            body: JSON.stringify(body)
        }, basic).then(function (request) {
            return fetch(url + endpoint, request).then(processData);
        })
    },
    put: function (endpoint: string, body: ObjectLiteral) {
        endpoint = encodeEnpoints(endpoint);
        return signRequest({
            method: 'PUT',
            url: url + endpoint,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        }).then(function (request) {
            return fetch(url + endpoint, request).then(processData);
        })
    },
    'delete': function (endpoint: string) {
        endpoint = encodeEnpoints(endpoint);
        return signRequest({
            method: 'DELETE',
            url: url + endpoint,
            headers: {}
        }).then(function (request) {
            return fetch(url + endpoint, request).then(processData);
        })
    },
};