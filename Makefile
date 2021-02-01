analysis_directories := $(shell ls | egrep 'policies|rules|helpers|models' | xargs)
# Find all *.yml files under schemas/ that are not in a '/tests/' path.
schema_files := $(shell find schemas/ -type f -name '*.yml' -and -not -wholename '*/tests/*' | sort | xargs)
# Last release tag
last_release := $(shell git tag --sort=version:refname --list 'v*' | tail -n1)
# Revision SHA1 at current commit
rev := $(shell git rev-parse HEAD)
# Release tag for current commit
release := $(shell git tag --points-at=$rev --sort=version:refname --list 'v*' | tail -n1)

ci:
	pipenv run $(MAKE) lint test

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	bandit -r $(analysis_directories) --skip B101  # allow assert statements in tests
	pylint $(analysis_directories) --disable=missing-docstring,bad-continuation,duplicate-code,import-error,W0511 --exit-zero

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run yapf $(analysis_directories) --in-place --parallel --recursive  --style google

install:
	pip3 install --user --upgrade pip
	pip3 install pipenv --upgrade
	pipenv install

test:
	@tmp=$$(mktemp -d); \
	for d in $(analysis_directories); \
	do \
		cp -r $$d "$$tmp"; \
	done; \
	current_dir=$$(pwd); \
	cd $$tmp; \
	panther_analysis_tool test ; \
	rm -r "$$tmp"; \
	cd $$current_dir;

test-single:
	@tmp=$$(mktemp -d); \
	cp -r global_helpers "$$tmp"; \
	cp -r $(pack) "$$tmp"; \
	panther_analysis_tool test --path "$$tmp"; \
	rm -r "$$tmp";


managed-schemas.zip:
	TMP=$$(mktemp -d); \
	for f in $(schema_files); do \
		echo "---"; \
		cat "$$f"; \
	done > "$$TMP/manifest.yml"; \
	sha256sum "$$TMP/manifest.yml" > "$$TMP/SHA256SUMS"; \
	mkdir -p dist; \
	rm -f dist/managed-schemas.zip; \
	if [ -v "$(release)" ]; then \
		echo "$(release)"; \
	else \
		echo "$(last_release)-$(rev)"; \
	fi | zip \
		--archive-comment \
		--junk-paths \
		--recurse-paths \
		--no-dir-entries \
		dist/managed-schemas.zip "$$TMP"; \
	rm -rf "$$TMP";

