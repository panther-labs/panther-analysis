# Contributing to `panther-analysis`

Thank you for your interest in contributing to Panther's open-source ruleset! We appreciate all types of contributions, including new detection rules, feature requests, and bug reports.

## What makes a good detection?

Please familiarize yourself with these helpful resources on writing high-quality Panther rules:

- The blog post Panther's founder, Jack Naglieri, wrote on [The Anatomy of a High Quality SIEM Rule](https://jacknaglieri.substack.com/p/hq-siem-rules)
- Panther's [Detection Documentation](https://docs.panther.com/detections)
- The `panther-analysis` [Style Guide](https://github.com/panther-labs/panther-analysis/blob/main/style_guides/STYLE_GUIDE.md)

Especially excellent contributions will be considered for a quarterly prize! We will announce a winner in the **Panther-Analysis Seasonal Newsletter**, where we share updates and celebrate contributions to Panther’s open-source ruleset.

## Testing your changes

Before submitting your pull request, make sure to:

- Write or update relevant unit tests
- Redact any sensitive information or PII from example logs
- Format, lint, and test your changes to ensure CI tests pass, using the following commands:

```bash
make fmt
make lint
make test
```

## Signing the Contributor License Agreement (CLA)

In order to clarify the intellectual property license granted with Contributions (as defined below) from any person or entity, Panther must have a Contributor License Agreement (“CLA”) on file that has been signed by each Contributor, indicating acceptance of the terms below.
Except for the license granted herein to Panther and recipients of software distributed by Panther, the Contributor (“you”) reserve all rights, title and interest in your Contributions. You can find the CLA [here](https://gist.githubusercontent.com/jacknagz/5d097acd8c6ea462361e2d375b87e519/raw/21d2f529bf52c07e7e5c7be8acfe2f7d66688eae/Panther-Labs-CLA.txt).

## Opening a Pull Request

1. Make desired detection changes. This may include creating new detections in existing log type directories, creating new log type directories, updating existing detections, etc
2. Commit both the Python and Metadata files
3. Write a clear commit message
4. Open a [Pull Request](https://github.com/panther-labs/panther-analysis/pulls) against the `develop` branch.
5. Once your PR has been approved by code owners, if you have merge permissions, merge it. If you do not have merge permissions, leave a comment requesting a code owner merge it for you

## Code of Conduct

Please follow the [Code of Conduct](https://github.com/panther-labs/panther-analysis/blob/main/CODE_OF_CONDUCT.md)
in all of your interactions with this project.

## Need help?

If you need assistance at any point, feel free to open a support ticket, or reach out to us on [Panther Community Slack](https://pnthr.io/community).

Thank you again for your contributions, and we look forward to working together!
