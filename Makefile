analysis_directories := $(shell ls | egrep 'policies|rules|helpers' | xargs)

ci:
	pipenv run $(MAKE) lint test

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	yapf $(analysis_directories) --diff --parallel --recursive --style google
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
	panther_analysis_tool test --path "$$tmp"; \
	rm -r "$$tmp";

test-single:
	@tmp=$$(mktemp -d); \
	cp -r global_helpers "$$tmp"; \
	cp -r $(pack) "$$tmp"; \
	panther_analysis_tool test --path "$$tmp"; \
	rm -r "$$tmp";
