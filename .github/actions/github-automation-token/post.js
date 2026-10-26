const { revokeToken } = require('./client');

revokeToken().catch(() => {
  process.stdout.write('::warning::token revocation failed; token will expire automatically\n');
});
