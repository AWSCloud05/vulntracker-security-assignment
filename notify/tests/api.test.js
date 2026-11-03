const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../src/index');
const config = require('../src/config');

const BASE_URL = `http://localhost:${config.PORT}`;
let server;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(config.PORT, resolve);
  });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

async function post(path, body, authenticated = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (authenticated) headers['X-Service-Key'] = config.SERVICE_KEY;

  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

async function get(path, authenticated = true) {
  const headers = {};
  if (authenticated) headers['X-Service-Key'] = config.SERVICE_KEY;

  const res = await fetch(`${BASE_URL}${path}`, { headers });
  return { status: res.status, body: await res.json() };
}

async function del(path, authenticated = true) {
  const headers = {};
  if (authenticated) headers['X-Service-Key'] = config.SERVICE_KEY;

  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'DELETE',
    headers,
  });
  return { status: res.status };
}


test('GET /health returns ok', async () => {
  const { status, body } = await get('/health');
  assert.equal(status, 200);
  assert.equal(body.status, 'ok');
});


test('POST /notify rejects requests without the service key', async () => {
  const { status } = await post(
    '/notify',
    { event: 'scan.created', payload: {} },
    false
  );
  assert.equal(status, 401);
});

test('GET /webhooks rejects requests without the service key', async () => {
  const { status } = await get('/webhooks', false);
  assert.equal(status, 401);
});

test('POST /webhooks rejects non-object metadata', async () => {
  const { status } = await post('/webhooks', {
    url: 'http://example.com/hook',
    events: ['scan.created'],
    metadata: ['unexpected'],
  });
  assert.equal(status, 400);
});

test('POST /webhooks registers a webhook', async () => {
  const { status, body } = await post('/webhooks', {
    url: 'http://example.com/hook',
    events: ['scan.created'],
  });
  assert.equal(status, 201);
  assert.ok(body.id);
  assert.equal(body.url, 'http://example.com/hook');
});

test('POST /webhooks rejects missing url', async () => {
  const { status } = await post('/webhooks', { events: ['scan.created'] });
  assert.equal(status, 400);
});

test('POST /webhooks rejects empty events array', async () => {
  const { status } = await post('/webhooks', { url: 'http://example.com', events: [] });
  assert.equal(status, 400);
});

test('GET /webhooks lists registered webhooks', async () => {
  const { status, body } = await get('/webhooks');
  assert.equal(status, 200);
  assert.ok(Array.isArray(body.webhooks));
});

test('DELETE /webhooks/:id removes a webhook', async () => {
  const { body } = await post('/webhooks', {
    url: 'http://example.com/deleteme',
    events: ['scan.updated'],
  });
  const { status } = await del(`/webhooks/${body.id}`);
  assert.equal(status, 204);
});

test('DELETE /webhooks/:id returns 404 for unknown id', async () => {
  const { status } = await del('/webhooks/non-existent-id');
  assert.equal(status, 404);
});

test('POST /notify requires event and payload', async () => {
  const { status } = await post('/notify', { event: 'scan.created' });
  assert.equal(status, 400);
});
