#!/usr/bin/env node
// R10 Chrome acceptance for original CatDesk. Local-only, invoked by the
// ignored Rust integration test. No OAuth tokens/codes or owner keys are logged.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { createInterface } from 'node:readline';

const base = process.env.CATDESK_R10_BASE;
const resource = process.env.CATDESK_R10_RESOURCE;
const chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const callbackPrefix = 'https://chatgpt.com/connector_platform_oauth_redirect';
const clientId = 'https://chatgpt.com/oauth/client.json';
const verifier = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~';
const assert = (condition, message) => { if (!condition) throw Error(message); };
// Cancel deadlines after a successful CDP response. Otherwise outstanding
// Promise.race sleep() timers hold the Node process open after acceptance.
async function deadline(promise, ms, label) {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error(label)), ms);
    });
    try { return await Promise.race([promise, timeout]); }
    finally { clearTimeout(timer); }
}
const requestHeaders = {'Mcp-Protocol-Version':'2026-07-28','Mcp-Method':'tools/list','Content-Type':'application/json'};
let browser, socket, profile, protocol;
const input = createInterface({input: process.stdin});
const messages = [];
let awaiting;
input.on('line', line => {
    if (awaiting) { const resolve = awaiting; awaiting = null; resolve(line); }
    else messages.push(line);
});
async function expectSignal(wanted) {
    const received = messages.length ? messages.shift() :
        await deadline(new Promise(resolve => {awaiting = resolve;}), 15000, 'Owner response timed out');
    assert(received === wanted, 'Incorrect owner control signal');
}

class CDP {
    constructor(ws) {
        this.ws = ws;
        this.id = 0;
        this.pending = new Map();
        this.listeners = new Map();
        ws.addEventListener('message', e => {
            const data = JSON.parse(e.data);
            if (data.id) {
                const resolver = this.pending.get(data.id);
                this.pending.delete(data.id);
                resolver?.(data);
            } else if (data.method) {
                for (const fn of this.listeners.get(data.method) ?? []) fn(data.params);
            }
        });
    }
    on(method, handler) {
        const handlers = this.listeners.get(method) ?? [];
        handlers.push(handler);
        this.listeners.set(method, handlers);
    }
    async send(method, params = {}) {
        const id = ++this.id;
        const response = new Promise(resolve => this.pending.set(id, resolve));
        this.ws.send(JSON.stringify({id, method, params}));
        const result = await deadline(response, 12000, 'CDP command timeout: ' + method);
        if (result.error) throw Error('CDP ' + method + ': ' + result.error.message);
        return result.result ?? {};
    }
}

async function waitForProfilePort(dir) {
    for (let i = 0; i < 130; i++) {
        try {
            const lines = (await readFile(join(dir,'DevToolsActivePort'),'utf8')).trim().split('\n');
            if (Number(lines[0]) > 0) return Number(lines[0]);
        } catch {}
        if (browser.exitCode !== null) throw Error('Chrome exited before DevTools startup');
        await sleep(100);
    }
    throw Error('Chrome DevTools port did not start');
}
async function evaluateValue(expression) {
    const response = await protocol.send('Runtime.evaluate', {
        expression, returnByValue: true, awaitPromise: true
    });
    if (response.exceptionDetails) throw Error('Chrome page evaluate failed');
    return response.result?.value;
}
async function readRequestId() {
    for (let i = 0; i < 100; i++) {
        const id = await evaluateValue(
            'document.querySelector(\'input[name="request_id"]\')?.value ?? null'
        );
        if (id) return id;
        await sleep(100);
    }
    throw Error('Chrome did not render OAuth consent form');
}
async function main() {
    assert(base?.startsWith('http://localhost:'), 'Only localhost OAuth acceptance allowed');
    assert(resource?.startsWith('https://'), 'Expected an HTTPS OAuth audience');
    profile = await mkdtemp(join(tmpdir(), 'original-catdesk-r10-chrome-'));
    browser = spawn(chrome, [
        '--headless=new', '--no-first-run', '--no-default-browser-check',
        '--disable-background-networking', '--disable-sync', '--disable-extensions',
        '--disable-component-update', '--no-proxy-server',
        '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
        '--user-data-dir=' + profile, 'about:blank'
    ], {stdio:['ignore','ignore','pipe']});
    browser.stderr.resume();
    const port = await waitForProfilePort(profile);
    const targetResponse = await fetch('http://127.0.0.1:' + port + '/json/new?about:blank', {method:'PUT'});
    assert(targetResponse.ok, 'Chrome rejected isolated browser target');
    const target = await targetResponse.json();
    socket = new WebSocket(target.webSocketDebuggerUrl);
    await deadline(new Promise((resolve,reject) => {
        socket.addEventListener('open', resolve, {once:true});
        socket.addEventListener('error', reject, {once:true});
    }), 8000, 'Chrome DevTools WebSocket timeout');
    protocol = new CDP(socket);
    await protocol.send('Page.enable');
    await protocol.send('Runtime.enable');
    await protocol.send('Network.enable');
    const approveDiagnostics = [];
    const approveRequestIds = new Set();
    protocol.on('Network.requestWillBeSent', p => {
        if (p.request.url.includes('/authorize/approve')) {
            approveRequestIds.add(p.requestId);
            approveDiagnostics.push('form-request=' + p.request.method);
            approveDiagnostics.push('origin-ok=' + (p.request.headers?.Origin === base));
            const h = Object.fromEntries(Object.entries(p.request.headers ?? {}).map(([k,v])=>[k.toLowerCase(),v]));
            approveDiagnostics.push('fetch-site=' + (h['sec-fetch-site'] ?? 'absent'));
            approveDiagnostics.push('fetch-mode=' + (h['sec-fetch-mode'] ?? 'absent'));
            approveDiagnostics.push('fetch-dest=' + (h['sec-fetch-dest'] ?? 'absent'));
        }
    });
    protocol.on('Network.requestWillBeSentExtraInfo', p => {
        if (approveRequestIds.has(p.requestId)) {
            const headers = Object.fromEntries(Object.entries(p.headers).map(([k,v]) => [k.toLowerCase(),v]));
            approveDiagnostics.push('extra-origin=' + (headers.origin ?? 'absent'));
            approveDiagnostics.push('extra-origin-ok=' + (headers.origin === base));
            approveDiagnostics.push('extra-fetch-site=' + (headers['sec-fetch-site'] ?? 'absent'));
            approveDiagnostics.push('extra-fetch-mode=' + (headers['sec-fetch-mode'] ?? 'absent'));
            approveDiagnostics.push('extra-fetch-dest=' + (headers['sec-fetch-dest'] ?? 'absent'));
            approveDiagnostics.push('cookie-present=' + Boolean(headers.cookie));
            approveDiagnostics.push('blocked-cookie-reasons=' + (p.associatedCookies ?? [])
                .flatMap(x => x.blockedReasons ?? []).join(','));
        }
    });
    protocol.on('Network.responseReceived', p => {
        if (p.response.url.includes('/authorize/approve')) {
            approveDiagnostics.push('form-response=' + p.response.status);
            approveDiagnostics.push('form-mime=' + p.response.mimeType);
        }
    });
    await protocol.send('Fetch.enable', {
        patterns: [
            {urlPattern: base + '/authorize/approve*', requestStage:'Response'},
            {urlPattern: callbackPrefix + '*', requestStage:'Request'}
        ]
    });
    let captureCallback;
    const redirected = new Promise(resolve => {captureCallback = resolve;});
    protocol.on('Fetch.requestPaused', p => {
        if (p.request.url === base + '/authorize/approve' && p.responseStatusCode) {
            const location = p.responseHeaders?.find(h => h.name.toLowerCase() === 'location')?.value;
            approveDiagnostics.push('intercept-response=' + p.responseStatusCode);
            if (p.responseStatusCode === 303 && location?.startsWith(callbackPrefix + '?')) {
                captureCallback(location);
            }
            // Cancel before the browser follows the external OAuth callback.
            protocol.send('Fetch.failRequest', {requestId:p.requestId,errorReason:'Aborted'})
                .catch(() => {});
        } else if (p.request.url.startsWith(callbackPrefix)) {
            // Defense in depth: never contact the real ChatGPT callback.
            captureCallback(p.request.url);
            protocol.send('Fetch.failRequest', {requestId:p.requestId,errorReason:'Aborted'})
                .catch(() => {});
        } else {
            protocol.send('Fetch.continueRequest', {requestId:p.requestId}).catch(() => {});
        }
    });

    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const state = 'chrome-native-browser-state-20261022-12345';
    const url = new URL(base + '/authorize');
    for (const [key,val] of Object.entries({
        response_type:'code', client_id:clientId,
        redirect_uri:callbackPrefix, resource, scope:'catdesk:read',
        state, code_challenge:challenge, code_challenge_method:'S256'
    })) url.searchParams.set(key,val);
    await protocol.send('Page.navigate', {url:url.href});
    const requestId = await readRequestId();
    assert(/^[A-Za-z0-9_-]{43}$/.test(requestId), 'Unexpected browser consent ID');
    const cookies = await protocol.send('Network.getCookies', {urls:[base]});
    const sessionCookie = cookies.cookies?.find(x=>x.name==='__Host-catdesk-oauth-consent');
    assert(sessionCookie && sessionCookie.secure && sessionCookie.httpOnly,
        'Real Chrome rejected the __Host- Secure HttpOnly localhost cookie');
    assert(sessionCookie.sameSite === 'Lax', 'SameSite policy missing');
    assert(!String(await evaluateValue('document.cookie')).includes('catdesk-oauth-consent'),
        'HttpOnly cookie became readable from page scripts');
    assert(!(await evaluateValue('document.querySelector(\'input[name="owner_key"]\')')),
        'Owner key field leaked into browser');
    console.log('BROWSER_CONSENT=' + requestId);
    await expectSignal('APPROVE');

    // Real Chrome browser form submission. Origin and Cookie are provided by
    // Chrome, not forged by a Rust HTTP test client.
    await protocol.send('Runtime.evaluate', {
        expression:'document.querySelector(\'form[action="/authorize/approve"]\').requestSubmit()'
    });
    const callback = await deadline(redirected, 10000,
        'Browser did not complete OAuth consent callback (' + approveDiagnostics.join(',') + ')');
    assert(callback.startsWith(callbackPrefix + '?'), 'Unexpected OAuth callback');
    const cb = new URL(callback);
    assert(cb.searchParams.get('state') === state, 'Client state was not preserved');
    const code = cb.searchParams.get('code');
    assert(code && code.length >= 40, 'Browser callback omitted authorization code');

    const exchange = await fetch(base + '/token', {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:new URLSearchParams({
            grant_type:'authorization_code',code,code_verifier:verifier,
            client_id:clientId,redirect_uri:callbackPrefix,resource
        })
    });
    assert(exchange.status === 200, 'Browser-issued code failed PKCE exchange');
    const json = await exchange.json();
    assert(json.scope === 'catdesk:read' && json.token_type === 'Bearer', 'Wrong token grants');
    const mcp = new URL(resource).pathname;
    const allowed = await fetch(base + mcp, {method:'POST',
        headers:{...requestHeaders,Authorization:'Bearer '+json.access_token},
        body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',
            params:{_meta:{
                'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                'io.modelcontextprotocol/clientCapabilities':{}
            }}})
    });
    assert(allowed.status === 200, 'Browser-issued Bearer cannot access MCP tools/list');
    const body = await allowed.json();
    assert(Array.isArray(body?.result?.tools), 'No MCP tool inventory returned');
    assert(body.result.tools.every(t=>['catdesk_instruction','read','search'].includes(t.name)),
        'MCP advertised actions beyond the owner-approved read-only scope');
    const replay = await fetch(base + '/token', {
        method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:new URLSearchParams({grant_type:'authorization_code',code,code_verifier:verifier,
            client_id:clientId,redirect_uri:callbackPrefix,resource})
    });
    assert(replay.status === 400, 'PKCE code replay accepted');
    console.log('BROWSER_TOKEN_VALID');
    await expectSignal('REVOKE');
    const revoked = await fetch(base + mcp, {headers:{Authorization:'Bearer '+json.access_token}});
    assert(revoked.status === 401, 'Token remained accepted after local owner revocation');
    console.log('BROWSER_R10_PASS');
}
try {
    await main();
} catch (error) {
    console.error('R10 Chrome acceptance failed: ' + error.message);
    console.log('BROWSER_ERROR=' + error.message);
    process.exitCode = 1;
} finally {
    try {socket?.close();} catch {}
    if (browser && browser.exitCode === null) { browser.kill('SIGTERM'); await sleep(400); }
    if (browser && browser.exitCode === null) browser.kill('SIGKILL');
    if (profile) await rm(profile, {recursive:true,force:true,maxRetries:3,retryDelay:100});
    input.close();
}
