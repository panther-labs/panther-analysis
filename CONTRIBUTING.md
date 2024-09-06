# Contributing to panther-analysis

Thank you for your interest in contributing to Panther's open-source ruleset!  We value and appreciate all contributions, whether they are bug reports, feature requests, or detection rule contributions.

## What Makes a Good Detection?

Please familiarize yourself with these helpful resources on writing high-quality Panther rules.  Especially excellent contributions will be considered for seasonal prizes!

- Jack's blog on [The Anatomy of a High Quality SIEM Rule](https://jacknaglieri.substack.com/p/hq-siem-rules)
- Panther's [Detection Documentation](https://docs.panther.com/detections)
- panther-analysis [Style Guide](https://github.com/panther-labs/panther-analysis/blob/main/STYLE_GUIDE.md)

## Testing Your Changes

Before submitting your pull request, make sure to:

- Write or update relevant unit tests.
- Redact any sensitive information or PII from example logs.
- Format, lint, and test your changes to ensure CI tests pass.

```bash
make fmt
make lint
make test
```

## Pull Request Process

1. Create new detections in the appropriate folder (or create your own) or make modifications to existing ones
2. Commit both the Python and Metadata files
3. Write a clear commit message
4. Open a [Pull Request](https://github.com/panther-labs/panther-analysis/pulls)
5. Incorporate feedback and merge once you have the sign-off of other code owners. If you do not have permission, you may request a reviewer to merge it for you.

## Code of Conduct

Please follow the [Code of Conduct](https://github.com/panther-labs/panther-analysis/blob/main/CODE_OF_CONDUCT.md)
in all of your interactions with the project.

## Need Help?

If you need assistance at any point, feel free to open a support ticket, or reach out to us on [Panther Community Slack](https://pnthr.io/community).

Thank you again for your contributions, and we look forward to working together!