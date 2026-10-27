const { mintToken } = require('./client');

// Workflow-command data must escape %, CR and LF or the annotation is truncated.
const escapeCommandData = (value) =>
  value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');

mintToken().catch((error) => {
  process.stdout.write(`::error::${escapeCommandData(error.message)}\n`);
  process.exitCode = 1;
});
