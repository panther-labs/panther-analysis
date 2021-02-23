# Find all *.yml files under schemas/ that are not in a '/tests/' path.
schema_files := $(shell find schemas/ -type f -name '*.yml' -and -not -wholename '*/tests/*' | sort | xargs)
# Last release tag
last_release := $(shell git tag --sort=version:refname --list 'v*' | tail -n1)
# Revision SHA1 at current commit
rev := $(shell git rev-parse HEAD)
# Release tag for current commit
release := $(shell git tag --points-at=$(rev) --sort=version:refname --list 'v*' | tail -n1)

dirs := $(shell ls | egrep 'policies|rules|helpers|models' | xargs)

ci:
	pipenv run $(MAKE) lint test

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	bandit -r $(dirs) --skip B101  # allow assert statements in tests
	pylint $(dirs) --disable=missing-docstring,bad-continuation,duplicate-code,import-error,W0511

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run isort ./
	pipenv run black --line-length=100 ./

install:
	pip3 install --user --upgrade pip
	pip3 install pipenv --upgrade
	pipenv install

test:
	panther_analysis_tool test

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
