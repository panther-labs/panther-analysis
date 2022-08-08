# Find all *.yml files under schemas/ that are not in a '/tests/' path.
schema_files := $(shell find schemas/ -type f -name '*.yml' -and -not -wholename '*/tests/*' | sort | xargs)
# Last release tag
last_release := $(shell git tag --sort=version:refname --list 'v*' | tail -n1)
# Revision SHA1 at current commit
rev := $(shell git rev-parse HEAD)
# Release tag for current commit
release := $(shell git tag --points-at=$(rev) --sort=version:refname --list 'v*' | tail -n1)

dirs := $(shell ls | egrep 'policies|rules|helpers|models|templates' | xargs)

ci:
	pipenv run $(MAKE) lint test

deps:
	pipenv install --dev

deps-update:
	pipenv update

lint:
	pipenv run bandit -r $(dirs) --skip B101  # allow assert statements in tests
	pipenv run pylint $(dirs) \
	  --disable=missing-docstring,duplicate-code,import-error,fixme,consider-iterating-dictionary,global-variable-not-assigned \
	  --load-plugins=pylint.extensions.mccabe \
	  --max-line-length=100

venv:
	pipenv install --dev

pat-update:
	pipenv update panther-analysis-tool

fmt:
	pipenv run isort --profile=black $(dirs)
	pipenv run black --line-length=100 $(dirs)
	prettier -w schemas schemas/**/*.yml

install:
	pipenv install --dev

test:
	pipenv run panther_analysis_tool test

managed-schemas:
	mkdir -p dist/managed-schemas; \
	for f in $(schema_files); do \
		echo "---"; \
		cat "$$f"; \
	done > "dist/managed-schemas/manifest.yml"; \
	sha256sum "dist/managed-schemas/manifest.yml" > "dist/managed-schemas/SHA256SUMS";

managed-schemas.zip: managed-schemas
	rm -f dist/managed-schemas.zip; \
	if [ "$(release)" != "" ]; then \
		echo "$(release)"; \
	else \
		echo "$(last_release)-$(rev)"; \
	fi | zip \
		--archive-comment \
		--junk-paths \
		--recurse-paths \
		-q \
		--no-dir-entries \
		dist/managed-schemas.zip "dist/managed-schemas";
