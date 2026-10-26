const fs = require('node:fs');

const REVOKE_URL = 'https://api.github.com/installation/token';
const OIDC_AUDIENCE = 'panther-github-app-token-broker';
const REQUEST_TIMEOUT_MS = 10_000;

function fail(message) {
  throw new Error(message);
}

function mask(value, stdout, invalidMessage) {
  if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) {
    fail(invalidMessage);
  }
  stdout.write(`::add-mask::${value}\n`);
}

function appendCommandFile(path, key, value) {
  if (!path) fail('GitHub Actions command file was unavailable');
  fs.appendFileSync(path, `${key}=${value}\n`, { encoding: 'utf8' });
}

// The token service URL is deployment-specific, so callers supply it; never echo it in errors.
function tokenUrlInput(env) {
  let url;
  try {
    url = new URL(env.INPUT_TOKEN_URL);
  } catch {
    fail('GitHub automation token service URL (token_url) was missing or invalid');
  }
  // Userinfo could surface in fetch errors, so reject it along with non-https schemes.
  if (url.protocol !== 'https:' || url.username || url.password) {
    fail('GitHub automation token service URL (token_url) was missing or invalid');
  }
  return url.href;
}

function repositoryInput(env) {
  const repository = env.INPUT_REPOSITORY || env.GITHUB_REPOSITORY;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || '')) {
    fail('GitHub automation token input was invalid');
  }
  return repository;
}

function permissionsInput(value) {
  let permissions;
  try {
    permissions = JSON.parse(value);
  } catch {
    fail('GitHub automation token input was invalid');
  }
  if (
    !permissions ||
    typeof permissions !== 'object' ||
    Array.isArray(permissions) ||
    Object.keys(permissions).length === 0 ||
    Object.entries(permissions).some(
      ([category, level]) => !category || !['read', 'write'].includes(level)
    )
  ) {
    fail('GitHub automation token input was invalid');
  }
  return permissions;
}

// Public annotations may only carry the status plus token service fields that match
// fixed patterns; never echo the raw response body.
async function failureDetails(response) {
  const details = [`HTTP ${response.status}`];
  try {
    const body = JSON.parse(await response.text());
    if (typeof body.phase === 'string' && /^[a-z_]{1,32}$/.test(body.phase)) {
      details.push(`phase=${body.phase}`);
    }
    if (typeof body.request_id === 'string' && /^[A-Za-z0-9_=-]{1,64}$/.test(body.request_id)) {
      details.push(`request_id=${body.request_id}`);
    }
  } catch {
    // Unreadable or non-JSON bodies fall back to the status alone.
  }
  return details.join(', ');
}

async function requestJson(fetchImpl, url, options, errorMessage) {
  const response = await fetchImpl(url, {
    ...options,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    fail(`${errorMessage} (${await failureDetails(response)})`);
  }
  let body;
  try {
    body = await response.json();
  } catch (error) {
    // Parse and read errors can quote the body or URL, so only a fixed label is surfaced.
    fail(`${errorMessage} (${error instanceof SyntaxError ? 'invalid' : 'unreadable'} response)`);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    fail(`${errorMessage} (invalid response)`);
  }
  return body;
}

async function mintToken(env = process.env, fetchImpl = globalThis.fetch, stdout = process.stdout) {
  const tokenUrl = tokenUrlInput(env);
  const repository = repositoryInput(env);
  const permissions = permissionsInput(env.INPUT_PERMISSIONS);
  if (!env.ACTIONS_ID_TOKEN_REQUEST_URL || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    fail('GitHub Actions OIDC was unavailable');
  }

  mask(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, stdout, 'OIDC request token was invalid');
  const oidcUrl = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  oidcUrl.searchParams.set('audience', OIDC_AUDIENCE);
  const oidcResponse = await requestJson(
    fetchImpl,
    oidcUrl,
    { headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } },
    'OIDC request failed'
  );
  const oidcToken = oidcResponse.value;
  if (typeof oidcToken !== 'string' || !oidcToken) fail('OIDC response was invalid');
  mask(oidcToken, stdout, 'OIDC response was invalid');

  const tokenResponse = await requestJson(
    fetchImpl,
    tokenUrl,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${oidcToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ repository, permissions }),
    },
    'token service request failed'
  );
  const { token, expires_at: expiresAt } = tokenResponse;
  // Keep a valid minted token revocable even when expiry metadata is rejected.
  mask(token, stdout, 'token service response was invalid');
  appendCommandFile(env.GITHUB_STATE, 'token', token);
  if (typeof expiresAt !== 'string' || !expiresAt) {
    fail('token service response was invalid');
  }
  appendCommandFile(env.GITHUB_OUTPUT, 'token', token);
}

async function revokeToken(env = process.env, fetchImpl = globalThis.fetch, stdout = process.stdout) {
  const token = env.STATE_token;
  if (!token) return;
  mask(token, stdout, 'saved token was invalid');
  try {
    const response = await fetchImpl(REVOKE_URL, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (response.ok || response.status === 401 || response.status === 404) return;
  } catch {
    // Report only the generic failure below; never include the token or HTTP body.
  }
  fail('token revocation failed');
}

module.exports = {
  mintToken,
  revokeToken,
};
