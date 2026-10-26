const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { mintToken, revokeToken } = require('./client');

const BROKER_URL = 'https://broker.example/token';

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'github-automation-token-'));
  const output = path.join(directory, 'output');
  const state = path.join(directory, 'state');
  const env = {
    GITHUB_REPOSITORY: 'example-org/source-repo',
    INPUT_TOKEN_URL: BROKER_URL,
    INPUT_PERMISSIONS: '{"statuses":"write"}',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://actions.example/oidc?request=1',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc-request-token',
    GITHUB_OUTPUT: output,
    GITHUB_STATE: state,
  };
  let printed = '';
  const stdout = { write: (text) => { printed += text; } };
  return { directory, env, output, state, stdout, printed: () => printed };
}

test('mints the exact repository scope, masks credentials, and saves cleanup state', async (t) => {
  const { directory, env, output, state, stdout, printed } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options });
    if (requests.length === 1) return response(200, { value: 'oidc-jwt' });
    return response(200, { token: 'installation-token', expires_at: '2026-10-13T22:00:00Z' });
  };

  await mintToken(env, fetchImpl, stdout);

  const oidcUrl = new URL(requests[0].url);
  assert.equal(oidcUrl.origin + oidcUrl.pathname, 'https://actions.example/oidc');
  assert.equal(oidcUrl.searchParams.get('request'), '1');
  assert.equal(oidcUrl.searchParams.get('audience'), 'panther-github-app-token-broker');
  assert.equal(requests[0].options.headers.Authorization, 'Bearer oidc-request-token');
  assert.equal(requests[1].url, BROKER_URL);
  assert.equal(requests[1].options.method, 'POST');
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    repository: 'example-org/source-repo',
    permissions: { statuses: 'write' },
  });
  assert.equal(requests[1].options.headers.Authorization, 'Bearer oidc-jwt');
  assert.equal(requests[1].options.headers['Content-Type'], 'application/json');
  assert.equal(fs.readFileSync(state, 'utf8'), 'token=installation-token\n');
  assert.equal(fs.readFileSync(output, 'utf8'), 'token=installation-token\n');
  assert.deepEqual(printed().trim().split('\n'), [
    '::add-mask::oidc-request-token',
    '::add-mask::oidc-jwt',
    '::add-mask::installation-token',
  ]);
});

test('bounds OIDC, broker and revocation requests with a 10 second timeout', async (t) => {
  const { directory, env, stdout } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const timeouts = [];
  const created = [];
  // Capture the requested duration and the signals created; restored when the test ends.
  t.mock.method(AbortSignal, 'timeout', (ms) => {
    timeouts.push(ms);
    const signal = new AbortController().signal;
    created.push(signal);
    return signal;
  });
  const used = [];
  const fetchImpl = async (url, options) => {
    used.push(options.signal);
    if (used.length === 1) return response(200, { value: 'oidc-jwt' });
    if (used.length === 2) return response(200, { token: 'installation-token', expires_at: '2026-10-13T22:00:00Z' });
    return response(204);
  };

  await mintToken(env, fetchImpl, stdout);
  await revokeToken({ STATE_token: 'installation-token' }, fetchImpl, stdout);

  assert.deepEqual(timeouts, [10_000, 10_000, 10_000]);
  assert.equal(used.length, created.length);
  used.forEach((signal, i) => assert.equal(signal, created[i]));
});

test('accepts an explicit cross-repository target', async (t) => {
  const { directory, env, stdout } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  env.INPUT_REPOSITORY = 'example-org/target-repo';
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options });
    if (requests.length === 1) return response(200, { value: 'oidc-jwt' });
    return response(200, { token: 'installation-token', expires_at: '2026-10-13T22:00:00Z' });
  };

  await mintToken(env, fetchImpl, stdout);
  assert.equal(JSON.parse(requests[1].options.body).repository, env.INPUT_REPOSITORY);
});

test('rejects malformed inputs before requesting OIDC', async (t) => {
  const { directory, env, stdout } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let calls = 0;
  const fetchImpl = async () => { calls += 1; };
  for (const permissions of ['', '{}', '[]', '{"statuses":"admin"}', '{"":"read"}']) {
    await assert.rejects(mintToken({ ...env, INPUT_PERMISSIONS: permissions }, fetchImpl, stdout), /GitHub automation token input/);
  }
  await assert.rejects(
    mintToken({ ...env, GITHUB_REPOSITORY: 'invalid' }, fetchImpl, stdout),
    /GitHub automation token input/
  );
  for (const repository of ['invalid', 'owner/', '/repo', 'a/b/c', 'owner/repo name', 'owner/repo\n']) {
    await assert.rejects(
      mintToken({ ...env, INPUT_REPOSITORY: repository }, fetchImpl, stdout),
      /GitHub automation token input/
    );
  }
  assert.equal(calls, 0);
});

test('requires an https token_url and never prints it', async (t) => {
  const { directory, env, stdout, printed } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let calls = 0;
  const fetchImpl = async () => { calls += 1; };
  for (const brokerUrl of [undefined, '', 'not a url', 'http://broker.example/secret-path', 'ftp://broker.example/secret-path', 'https://user:secret-password@broker.example/token', 'https://:secret-password@broker.example/token']) {
    await assert.rejects(
      mintToken({ ...env, INPUT_TOKEN_URL: brokerUrl }, fetchImpl, stdout),
      (error) => /token_url\) was missing or invalid/.test(error.message) && !/secret-(path|password)/.test(error.message)
    );
  }
  assert.equal(calls, 0);
  assert.doesNotMatch(printed(), /secret-(path|password)/);
});

test('rejects missing OIDC credentials and malformed OIDC tokens before broker access', async (t) => {
  const { directory, env, output, state, stdout } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let calls = 0;
  const fetchImpl = async () => { calls += 1; return response(200, {}); };

  for (const missing of ['ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN']) {
    await assert.rejects(mintToken({ ...env, [missing]: '' }, fetchImpl, stdout), /OIDC was unavailable/);
  }
  assert.equal(calls, 0);
  await assert.rejects(mintToken(env, fetchImpl, stdout), /OIDC response was invalid/);
  assert.equal(calls, 1);
  assert.equal(fs.existsSync(state), false);
  assert.equal(fs.existsSync(output), false);
});

test('identifies which OIDC credential failed the line-break check', async (t) => {
  const { directory, env, stdout } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return response(200, { value: 'oidc\njwt' });
  };

  await assert.rejects(
    mintToken({ ...env, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'request\ntoken' }, fetchImpl, stdout),
    /OIDC request token was invalid/
  );
  assert.equal(calls, 0);
  await assert.rejects(mintToken(env, fetchImpl, stdout), /OIDC response was invalid/);
  assert.equal(calls, 1);
});

test('reports only HTTP status and validated broker fields without writing a token', async (t) => {
  const oidc = response(200, { value: 'oidc-jwt' });
  const policyBody = JSON.stringify({ message: 'unauthorized', phase: 'policy', request_id: 'FfjmnhkIvHcEPZA=' });
  const unsafeBody = JSON.stringify({
    message: 'leak installation-token',
    phase: 'policy\n::error::injected',
    request_id: 'x'.repeat(65),
    token: 'installation-token',
  });
  const brokerFailure = (fields) => new Response(JSON.stringify(fields), { status: 502 });
  const privateBody = '<html>PRIVATE-MARKER internal.example 10.0.0.1</html>';
  const networkError = new TypeError('fetch failed');
  const bodyReadError = new TypeError('body read failed');
  const leakyReadError = new TypeError(`terminated ${BROKER_URL} PRIVATE-MARKER`);
  const timeoutError = new DOMException('request timed out', 'TimeoutError');
  const cases = [
    {
      name: 'OIDC denial',
      replies: [new Response('OIDC denied', { status: 403 })],
      error: { message: 'OIDC request failed (HTTP 403)' },
    },
    {
      name: 'broker policy denial',
      replies: [oidc, new Response(policyBody, { status: 401 })],
      error: { message: 'token service request failed (HTTP 401, phase=policy, request_id=FfjmnhkIvHcEPZA=)' },
    },
    {
      name: 'broker non-JSON failure',
      replies: [oidc, new Response('Bad gateway', { status: 502 })],
      error: { message: 'token service request failed (HTTP 502)' },
    },
    {
      name: 'broker valid phase with disallowed request_id character',
      replies: [oidc, brokerFailure({ phase: 'policy', request_id: 'req!1' })],
      error: { message: 'token service request failed (HTTP 502, phase=policy)' },
    },
    {
      name: 'broker disallowed phase with valid request_id',
      replies: [oidc, brokerFailure({ phase: 'Policy-1', request_id: 'req-1' })],
      error: { message: 'token service request failed (HTTP 502, request_id=req-1)' },
    },
    {
      name: 'broker over-long phase with valid request_id',
      replies: [oidc, brokerFailure({ phase: 'a'.repeat(33), request_id: 'req-1' })],
      error: { message: 'token service request failed (HTTP 502, request_id=req-1)' },
    },
    {
      name: 'broker array phase with valid request_id',
      replies: [oidc, brokerFailure({ phase: ['policy'], request_id: 'req-1' })],
      error: { message: 'token service request failed (HTTP 502, request_id=req-1)' },
    },
    {
      name: 'broker non-string phase and request_id',
      replies: [oidc, brokerFailure({ phase: 1, request_id: ['req-1'] })],
      error: { message: 'token service request failed (HTTP 502)' },
    },
    {
      name: 'broker unsafe fields',
      replies: [oidc, new Response(unsafeBody, { status: 502 })],
      error: { message: 'token service request failed (HTTP 502)' },
    },
    { name: 'OIDC array body', replies: [response(200, [])], error: { message: 'OIDC request failed (invalid response)' } },
    { name: 'broker null body', replies: [oidc, response(200, null)], error: { message: 'token service request failed (invalid response)' } },
    { name: 'OIDC fetch failure', replies: [networkError], error: networkError },
    { name: 'broker timeout', replies: [oidc, timeoutError], error: timeoutError },
    {
      name: 'OIDC malformed success',
      replies: [new Response(privateBody)],
      error: { message: 'OIDC request failed (invalid response)' },
    },
    {
      name: 'broker malformed success',
      replies: [oidc, new Response(privateBody)],
      error: { message: 'token service request failed (invalid response)' },
    },
    {
      name: 'OIDC successful body read failure',
      replies: [{ ok: true, status: 200, json: async () => { throw leakyReadError; } }],
      error: { message: 'OIDC request failed (unreadable response)' },
    },
    {
      name: 'broker successful body read failure',
      replies: [oidc, { ok: true, status: 200, json: async () => { throw leakyReadError; } }],
      error: { message: 'token service request failed (unreadable response)' },
    },
    {
      name: 'broker successful body read timeout',
      replies: [oidc, { ok: true, status: 200, json: async () => { throw timeoutError; } }],
      error: { message: 'token service request failed (unreadable response)' },
    },
    {
      name: 'broker error body read failure',
      replies: [oidc, { ok: false, status: 502, text: async () => { throw bodyReadError; } }],
      error: { message: 'token service request failed (HTTP 502)' },
    },
  ];

  for (const { name, replies, error } of cases) {
    await t.test(name, async (t) => {
      const { directory, env, output, state, stdout } = fixture();
      t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
      let calls = 0;
      const fetchImpl = async () => {
        const reply = replies[calls++];
        if (reply instanceof Error) throw reply;
        return reply;
      };

      await assert.rejects(mintToken(env, fetchImpl, stdout), error);
      assert.equal(calls, replies.length);
      assert.equal(fs.existsSync(state), false);
      assert.equal(fs.existsSync(output), false);
    });
  }
});

test('accepts broker response metadata beyond the required token fields', async (t) => {
  const { directory, env, output, state, stdout } = fixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    if (calls === 1) return response(200, { value: 'oidc-jwt' });
    return response(200, { token: 'installation-token', expires_at: 'later', repository: 'example-org/source-repo' });
  };

  await mintToken(env, fetchImpl, stdout);
  assert.equal(fs.readFileSync(state, 'utf8'), 'token=installation-token\n');
  assert.equal(fs.readFileSync(output, 'utf8'), 'token=installation-token\n');
});

test('rejects malformed GitHub automation tokens without writing a token or partial mask', async (t) => {
  const bodies = [
    { token: 1, expires_at: 'later' },
    { token: '', expires_at: 'later' },
    { token: 'line-one\nline-two', expires_at: 'later' },
  ];

  for (const body of bodies) {
    await t.test(JSON.stringify(body), async (t) => {
      const { directory, env, output, state, stdout, printed } = fixture();
      t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
      let calls = 0;
      const fetchImpl = async () => {
        calls += 1;
        if (calls === 1) return response(200, { value: 'oidc-jwt' });
        return response(200, body);
      };

      await assert.rejects(mintToken(env, fetchImpl, stdout), /token service response was invalid/);
      assert.equal(fs.existsSync(state), false);
      assert.equal(fs.existsSync(output), false);
      assert.doesNotMatch(printed(), /line-one|installation-token/);
    });
  }
});

test('rejected expiry metadata retains masking and post-revocation state without consumer outputs', async (t) => {
  for (const expiresAt of [undefined, 1, '']) {
    await t.test(String(expiresAt), async (t) => {
      const { directory, env, output, state, stdout, printed } = fixture();
      t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
      let calls = 0;
      const fetchImpl = async () => {
        calls += 1;
        if (calls === 1) return response(200, { value: 'oidc-jwt' });
        return response(200, { token: 'installation-token', expires_at: expiresAt });
      };

      await assert.rejects(mintToken(env, fetchImpl, stdout), /token service response was invalid/);
      assert.match(printed(), /::add-mask::installation-token\n/);
      assert.equal(fs.readFileSync(state, 'utf8'), 'token=installation-token\n');
      assert.equal(fs.existsSync(output), false);
      const savedToken = fs.readFileSync(state, 'utf8').trim().slice('token='.length);
      const revoke = async (url, options) => {
        assert.equal(url, 'https://api.github.com/installation/token');
        assert.equal(options.headers.Authorization, 'Bearer installation-token');
        return response(204);
      };
      await revokeToken({ STATE_token: savedToken }, revoke, stdout);
    });
  }
});

test('rejects missing GitHub command files', async (t) => {
  for (const missing of ['GITHUB_STATE', 'GITHUB_OUTPUT']) {
    await t.test(missing, async (t) => {
      const { directory, env, output, state, stdout } = fixture();
      t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
      delete env[missing];
      let calls = 0;
      const fetchImpl = async () => {
        calls += 1;
        if (calls === 1) return response(200, { value: 'oidc-jwt' });
        return response(200, { token: 'installation-token', expires_at: 'later' });
      };

      await assert.rejects(mintToken(env, fetchImpl, stdout), /command file was unavailable/);
      assert.equal(fs.existsSync(output), false);
      assert.equal(fs.existsSync(state), missing === 'GITHUB_OUTPUT');
    });
  }
});

test('post revokes only its saved token and tolerates an expired token', async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options });
    return response(204);
  };
  let printed = '';
  const stdout = { write: (text) => { printed += text; } };

  await revokeToken({ STATE_token: 'installation-token' }, fetchImpl, stdout);
  assert.equal(requests[0].url, 'https://api.github.com/installation/token');
  assert.equal(requests[0].options.method, 'DELETE');
  assert.equal(requests[0].options.headers.Authorization, 'Bearer installation-token');
  assert.equal(printed, '::add-mask::installation-token\n');
  await revokeToken({}, fetchImpl, stdout);
  assert.equal(requests.length, 1);
  await revokeToken({ STATE_token: 'already-expired' }, async () => response(401), stdout);
  await revokeToken({ STATE_token: 'already-gone' }, async () => response(404), stdout);
  await assert.rejects(
    revokeToken({ STATE_token: 'installation-token' }, async () => response(503), stdout),
    { message: 'token revocation failed' }
  );
  await assert.rejects(
    revokeToken({ STATE_token: 'installation-token' }, async () => { throw new Error('private network detail'); }, stdout),
    { message: 'token revocation failed' }
  );
  assert.doesNotMatch(printed, /private network detail/);
});

test('entrypoints fail mint errors and warn without failing the job on cleanup errors', () => {
  const main = spawnSync(process.execPath, [path.join(__dirname, 'main.js')], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_REPOSITORY: 'example-org/source-repo', INPUT_TOKEN_URL: BROKER_URL, INPUT_PERMISSIONS: '{}' },
  });
  assert.equal(main.status, 1);
  assert.match(main.stdout, /::error::GitHub automation token input was invalid/);

  const post = spawnSync(process.execPath, [
    '-e',
    'globalThis.fetch = async () => ({ ok: false, status: 503 }); require(process.argv[1]);',
    path.join(__dirname, 'post.js'),
  ], { encoding: 'utf8', env: { ...process.env, STATE_token: 'installation-token' } });
  assert.equal(post.status, 0);
  assert.equal(
    post.stdout,
    '::add-mask::installation-token\n::warning::token revocation failed; token will expire automatically\n'
  );

  const noToken = spawnSync(process.execPath, [path.join(__dirname, 'post.js')], {
    encoding: 'utf8', env: { ...process.env, STATE_token: '' },
  });
  assert.equal(noToken.status, 0);
  assert.equal(noToken.stdout, '');
});

test('main annotates broker HTTP status and validated fields only', () => {
  const main = spawnSync(process.execPath, [
    '-e',
    `globalThis.fetch = async (url) => String(url).startsWith('https://actions.example/')
      ? { ok: true, status: 200, json: async () => ({ value: 'oidc-jwt' }) }
      : new Response(JSON.stringify({
          message: 'unauthorized', phase: 'policy', request_id: 'FfjmnhkIvHcEPZA='
        }), { status: 401 });
    require(process.argv[1]);`,
    path.join(__dirname, 'main.js'),
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GITHUB_REPOSITORY: 'example-org/source-repo',
      INPUT_TOKEN_URL: BROKER_URL,
      INPUT_PERMISSIONS: '{"statuses":"write"}',
      ACTIONS_ID_TOKEN_REQUEST_URL: 'https://actions.example/oidc',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc-request-token',
    },
  });
  assert.equal(main.status, 1);
  assert.equal(main.stdout, [
    '::add-mask::oidc-request-token',
    '::add-mask::oidc-jwt',
    '::error::token service request failed (HTTP 401, phase=policy, request_id=FfjmnhkIvHcEPZA=)',
    '',
  ].join('\n'));
  assert.equal(main.stderr, '');
});

test('main escapes %, CR and LF in a multiline error message', () => {
  const main = spawnSync(process.execPath, [
    '-e',
    `globalThis.fetch = async (url) => String(url).startsWith('https://actions.example/')
      ? { ok: true, status: 200, json: async () => ({ value: 'oidc-jwt' }) }
      : Promise.reject(new Error('denied 100%\\r\\nsecond line'));
    require(process.argv[1]);`,
    path.join(__dirname, 'main.js'),
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GITHUB_REPOSITORY: 'example-org/source-repo',
      INPUT_TOKEN_URL: BROKER_URL,
      INPUT_PERMISSIONS: '{"statuses":"write"}',
      ACTIONS_ID_TOKEN_REQUEST_URL: 'https://actions.example/oidc',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc-request-token',
    },
  });
  assert.equal(main.status, 1);
  assert.match(main.stdout, /^::error::denied 100%25%0D%0Asecond line$/m);
});

test('main never annotates malformed success bodies', () => {
  const main = spawnSync(process.execPath, [
    '-e',
    `globalThis.fetch = async () => new Response('<html>PRIVATE-MARKER internal.example 10.0.0.1</html>');
    require(process.argv[1]);`,
    path.join(__dirname, 'main.js'),
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      GITHUB_REPOSITORY: 'example-org/source-repo',
      INPUT_TOKEN_URL: BROKER_URL,
      INPUT_PERMISSIONS: '{"statuses":"write"}',
      ACTIONS_ID_TOKEN_REQUEST_URL: 'https://actions.example/oidc',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'oidc-request-token',
    },
  });
  assert.equal(main.status, 1);
  assert.equal(main.stdout, '::add-mask::oidc-request-token\n::error::OIDC request failed (invalid response)\n');
  assert.doesNotMatch(main.stdout + main.stderr, /PRIVATE-MARKER|internal\.example/);
});
