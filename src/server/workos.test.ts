import assert from 'node:assert/strict';
import { test } from 'node:test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { WorkOSAuth, workOSOptionsFromEnv } from './workos.js';
import { connectHttpTransport, connectSSETransport } from './transport.js';
import { fixedArgoCDCredentials } from './credentials.js';

const workos = {
  authkitDomain: 'https://issuer.example.com',
  resourceUrl: 'https://mcp.example.com/mcp',
  allowedEmailDomain: 'example.com'
};

test('WorkOS validates configuration before exposing a listener', () => {
  for (const change of [
    { authkitDomain: 'http://issuer.example.com' },
    { authkitDomain: 'https://issuer.example.com/path' },
    { authkitDomain: 'https://user@issuer.example.com' },
    { resourceUrl: 'https://mcp.example.com/other' },
    { resourceUrl: 'https://mcp.example.com/mcp?query=1' },
    { allowedEmailDomain: '*.example.com' },
    { allowedEmailDomain: 'user@example.com' }
  ]) {
    assert.throws(() => new WorkOSAuth({ ...workos, ...change }));
  }
  assert.throws(() => connectSSETransport({ port: 3000, workos }), /stateless HTTP/);
  assert.throws(() => connectHttpTransport({ port: 3000, workos }), /stateless/);
});

test('native WorkOS authentication protects the actual MCP transport', async (t) => {
  const previousEnv = { ...process.env };
  const directory = mkdtempSync(join(tmpdir(), 'argocd-workos-test-'));
  const file = join(directory, 'token');
  writeFileSync(file, 'backend-token-one\n');
  process.env.ARGOCD_API_TOKEN_FILE = file;
  process.env.ARGOCD_BASE_URL = 'https://argocd.example.com';
  process.env.MCP_READ_ONLY = 'true';
  delete process.env.ARGOCD_API_TOKEN;
  delete process.env.ARGOCD_TOKEN_REGISTRY_PATH;
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const key = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };
  let profile: unknown = { sub: 'user_test', email: 'reader@example.com', email_verified: true };
  let userinfoStatus = 201;
  let providerFailure = false;
  let oversized = false;
  const backendTokens: string[] = [];
  const providerTokens: string[] = [];
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    if (url.startsWith(workos.authkitDomain)) {
      assert.equal(init?.redirect, 'error');
      assert.ok(init?.signal);
      if (providerFailure) throw new Error('provider offline');
      if (url.endsWith('/oauth2/jwks')) return Response.json({ keys: [key] });
      if (url.endsWith('/oauth2/userinfo')) {
        assert.equal(init?.method, 'POST');
        providerTokens.push(headers.get('authorization') || '');
        return oversized
          ? new Response('x'.repeat(65 * 1024))
          : Response.json(profile, { status: userinfoStatus });
      }
      if (url.endsWith('/.well-known/oauth-authorization-server')) {
        return Response.json({
          issuer: workos.authkitDomain,
          token_endpoint: `${workos.authkitDomain}/oauth2/token`
        });
      }
    }
    if (url.startsWith('https://argocd.example.com/api/v1/')) {
      backendTokens.push(headers.get('authorization') || '');
      assert.equal(headers.get('cookie'), null);
      return Response.json({ items: [] });
    }
    throw new Error('Unexpected network destination');
  });
  const sign = (claims: Record<string, unknown> = {}, kid = 'test-key') =>
    new SignJWT({
      iss: workos.authkitDomain,
      aud: workos.resourceUrl,
      sub: 'user_test',
      exp: Math.floor(Date.now() / 1000) + 300,
      client_id: 'client_test',
      sid: 'session_test',
      scope: 'openid email profile offline_access',
      ...claims
    })
      .setProtectedHeader({ alg: 'RS256', kid })
      .sign(privateKey);
  const goodToken = await sign();
  const probe = http.createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  const server = connectHttpTransport({ port, workos, stateless: true });
  await new Promise((resolve) => server.once('listening', resolve));
  const request = (
    options: {
      path?: string;
      method?: string;
      token?: string | null;
      headers?: Record<string, string>;
      body?: unknown;
    } = {}
  ): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> =>
    new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          path: options.path ?? '/mcp',
          method: options.method ?? 'POST',
          headers: {
            host: 'mcp.example.com',
            accept: 'application/json, text/event-stream',
            'content-type': 'application/json',
            ...(options.token !== null
              ? { authorization: `Bearer ${options.token ?? goodToken}` }
              : {}),
            ...options.headers
          }
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => (body += chunk));
          res.on('end', () => resolve({ status: res.statusCode!, headers: res.headers, body }));
        }
      );
      req.on('error', reject);
      req.end(options.body === undefined ? undefined : JSON.stringify(options.body));
    });
  const rpc = (method: string, params?: unknown) => ({ jsonrpc: '2.0', id: 1, method, params });
  const result = (body: string) =>
    JSON.parse(body.startsWith('event:') ? body.split('data: ')[1].trim() : body);
  try {
    const challenge = await request({ token: null });
    assert.equal(challenge.status, 401);
    assert.match(
      challenge.headers['www-authenticate']!,
      /https:\/\/mcp.example.com\/\.well-known\/oauth-protected-resource\/mcp/
    );
    for (const method of ['GET', 'DELETE'])
      assert.equal((await request({ method, token: null })).status, 401);
    for (const path of [
      '/.well-known/oauth-protected-resource',
      '/.well-known/oauth-protected-resource/mcp'
    ]) {
      const metadata = await request({ path, method: 'GET', token: null });
      assert.equal(metadata.status, 200);
      assert.equal(JSON.parse(metadata.body).resource, workos.resourceUrl);
    }
    assert.equal(
      (
        await request({
          path: '/.well-known/oauth-authorization-server',
          method: 'GET',
          token: null
        })
      ).status,
      200
    );
    assert.equal(
      (
        await request({
          path: '/healthz',
          method: 'GET',
          token: null,
          headers: { host: '10.0.0.1' }
        })
      ).status,
      200
    );
    assert.equal((await request({ headers: { host: 'evil.example.com' } })).status, 403);
    assert.equal((await request({ headers: { origin: 'https://evil.example.com' } })).status, 403);
    assert.equal((await request({ token: 'not-a-jwt' })).status, 401);
    for (const claims of [
      { aud: 'https://other.example.com/mcp' },
      { aud: [workos.resourceUrl] },
      { iss: 'https://other.example.com' },
      { exp: 1 },
      { exp: undefined },
      { nbf: Math.floor(Date.now() / 1000) + 600 },
      { sub: 'client_machine' },
      { client_id: '' },
      { sid: '' },
      { scope: 'openid' }
    ])
      assert.equal((await request({ token: await sign(claims) })).status, 401);
    assert.equal((await request({ token: await sign({}, 'unknown-key') })).status, 401);
    for (const invalid of [
      { sub: 'user_other', email: 'reader@example.com', email_verified: true },
      { sub: 'user_test', email: 'reader@example.com', email_verified: false },
      { sub: 'user_test', email: 'reader@example.com.evil.test', email_verified: true },
      { sub: 'user_test', email: 'reader@sub.example.com', email_verified: true }
    ]) {
      profile = invalid;
      assert.equal((await request()).status, 401);
    }
    profile = { sub: 'user_test', email: 'reader@EXAMPLE.COM', email_verified: true };
    userinfoStatus = 403;
    assert.equal((await request()).status, 401);
    userinfoStatus = 201;
    oversized = true;
    assert.equal((await request()).status, 401);
    oversized = false;
    providerFailure = true;
    assert.equal((await request()).status, 401);
    providerFailure = false;
    const initialized = await request({
      body: rpc('initialize', {
        protocolVersion: '2025-03-26',
        capabilities: {},
        clientInfo: { name: 'test', version: '1' }
      })
    });
    assert.equal(initialized.status, 200);
    assert.equal(initialized.headers['mcp-session-id'], undefined);
    const discovered = result((await request({ body: rpc('tools/list') })).body);
    assert.ok(
      discovered.result.tools.some((tool: { name: string }) => tool.name === 'list_applications')
    );
    assert.ok(
      !discovered.result.tools.some((tool: { name: string }) => tool.name === 'sync_application')
    );
    const call = rpc('tools/call', { name: 'list_applications', arguments: {} });
    const read = await request({
      body: call,
      headers: {
        'x-argocd-base-url': 'https://evil.example.com',
        'x-argocd-api-token': 'caller-token',
        cookie: 'session=caller',
        'proxy-authorization': 'Bearer caller'
      }
    });
    assert.equal(result(read.body).result.isError, false);
    assert.deepEqual(backendTokens, ['Bearer backend-token-one']);
    assert.ok(providerTokens.every((token) => token.startsWith('Bearer ey')));
    const override = await request({
      body: rpc('tools/call', {
        name: 'list_applications',
        arguments: { argocdBaseUrl: 'https://evil.example.com' }
      })
    });
    assert.equal(result(override.body).result.isError, true);
    assert.equal(backendTokens.length, 1);
    writeFileSync(file, 'backend-token-two');
    await request({ body: call });
    assert.equal(backendTokens.at(-1), 'Bearer backend-token-two');
    writeFileSync(file, '');
    assert.equal((await request({ body: call })).status, 503);
    writeFileSync(file, 'backend-token-two');
    assert.throws(
      () => connectHttpTransport({ port, stateless: true, workos, authToken: 'bypass' }),
      /cannot be combined/
    );
    process.env.ARGOCD_API_TOKEN = 'conflicting-token';
    assert.throws(fixedArgoCDCredentials, /only one/);
    delete process.env.ARGOCD_API_TOKEN;
    process.env.ARGOCD_TOKEN_REGISTRY_PATH = 'registry.json';
    assert.throws(fixedArgoCDCredentials, /registry/);
    process.env.WORKOS_AUTHKIT_DOMAIN = workos.authkitDomain;
    delete process.env.WORKOS_RESOURCE_URL;
    delete process.env.WORKOS_ALLOWED_EMAIL_DOMAIN;
    assert.throws(workOSOptionsFromEnv, /requires/);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    for (const name of Object.keys(process.env))
      if (!(name in previousEnv)) delete process.env[name];
    Object.assign(process.env, previousEnv);
    rmSync(directory, { recursive: true, force: true });
  }
});
