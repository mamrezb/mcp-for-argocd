import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { gzipSync } from 'node:zlib';
import { HttpClient } from './http.js';

const limit = 10 * 1024 * 1024;
const encoder = new TextEncoder();

function chunkedBody(chunks: Uint8Array[], cancelled: () => void) {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index < chunks.length) controller.enqueue(chunks[index++]);
      else controller.close();
    },
    cancel: cancelled
  });
}

test('JSON backend responses preserve metadata, query parameters and credentials', async (t) => {
  t.mock.method(globalThis, 'fetch', async (url: URL, init: RequestInit) => {
    assert.equal(url.toString(), 'https://argocd.example.com/api/test?search=example');
    assert.equal(new Headers(init.headers).get('authorization'), 'Bearer backend-token');
    assert.ok(init.signal);
    return Response.json({ items: [1] }, { status: 201, headers: { 'x-result': 'example' } });
  });
  const response = await new HttpClient('https://argocd.example.com', 'backend-token').get(
    '/api/test',
    { search: 'example' }
  );
  assert.equal(response.status, 201);
  assert.equal(response.headers.get('x-result'), 'example');
  assert.deepEqual(response.body, { items: [1] });
});

test('JSON responses accept the byte limit and reject oversized chunked bodies', async (t) => {
  const client = new HttpClient('https://argocd.example.com', 'token');
  const content = 'x'.repeat(limit - 2);
  let oversized = false;
  let cancelled = false;
  const chunk = new Uint8Array(1024 * 1024).fill(32);
  t.mock.method(globalThis, 'fetch', async () =>
    oversized
      ? new Response(
          chunkedBody(
            Array.from({ length: 12 }, () => chunk),
            () => (cancelled = true)
          )
        )
      : new Response(JSON.stringify(content))
  );
  assert.equal((await client.get('/at-limit')).body, content);
  oversized = true;
  await assert.rejects(
    client.get('/oversized'),
    /response body exceeds maximum size of 10485760 bytes/
  );
  assert.equal(cancelled, true);
});

test('streamed responses reject oversized lines without requiring a newline or Content-Length', async (t) => {
  let cancelled = false;
  const chunk = new Uint8Array(1024 * 1024).fill(32);
  t.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(
        chunkedBody(
          Array.from({ length: 12 }, () => chunk),
          () => (cancelled = true)
        )
      )
  );
  await assert.rejects(
    new HttpClient('https://argocd.example.com', 'token').getStream('/oversized'),
    /response body exceeds maximum size of 10485760 bytes/
  );
  assert.equal(cancelled, true);
});

test('streamed responses accept the byte limit and preserve split UTF-8 records', async (t) => {
  const record = encoder.encode('{"result":{"line":"héllo"}}\n');
  const split = record.indexOf(0xc3) + 1;
  const padding = new Uint8Array(limit - record.length).fill(32);
  t.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(chunkedBody([record.slice(0, split), record.slice(split), padding], () => {}))
  );
  const records: unknown[] = [];
  await new HttpClient('https://argocd.example.com', 'token').getStream('/logs', null, (line) => {
    records.push(line);
  });
  assert.deepEqual(records, [{ line: 'héllo' }]);
});

test('stream readers are cancelled when parsing or callbacks fail', async (t) => {
  let callbackFails = false;
  let cancelled = false;
  t.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            const content = callbackFails ? '{"result":{}}\n' : 'invalid JSON\n';
            controller.enqueue(encoder.encode(content));
          },
          cancel() {
            cancelled = true;
          }
        })
      )
  );
  for (callbackFails of [false, true]) {
    cancelled = false;
    await assert.rejects(
      new HttpClient('https://argocd.example.com', 'token').getStream('/logs', null, () => {
        throw new Error('callback failed');
      })
    );
    assert.equal(cancelled, true);
  }
});

test('response byte limits also apply to decompressed backend bodies', async (t) => {
  const body = gzipSync(JSON.stringify('x'.repeat(limit)));
  const server = http.createServer((_req, res) => {
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-encoding': 'gzip',
      'content-length': body.byteLength
    });
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  const { port } = server.address() as AddressInfo;
  const client = new HttpClient(`http://127.0.0.1:${port}`, 'token');
  await assert.rejects(client.get('/json'), /response body exceeds maximum size/);
  await assert.rejects(client.getStream('/stream'), /response body exceeds maximum size/);
});

test(
  'backend deadlines abort stalled headers and bodies for JSON and streams',
  { timeout: 3000 },
  async (t) => {
    const timeout = AbortSignal.timeout.bind(AbortSignal);
    t.mock.method(AbortSignal, 'timeout', (milliseconds: number) => {
      assert.equal(milliseconds, 10_000);
      return timeout(100);
    });
    const server = http.createServer((req, res) => {
      if (req.url === '/body') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.write(' ');
      }
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const { port } = server.address() as AddressInfo;
    const client = new HttpClient(`http://127.0.0.1:${port}`, 'token');
    for (const streaming of [false, true]) {
      for (const path of ['/headers', '/body']) {
        await assert.rejects(
          streaming ? client.getStream(path) : client.get(path),
          (error: Error) => ['TimeoutError', 'AbortError'].includes(error.name)
        );
      }
    }
  }
);
