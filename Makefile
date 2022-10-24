dirs := $(shell ls | egrep 'policies|rules|helpers|models|templates' | xargs)
target_mount_dir := "/home/panther-analysis" # /$(shell basename $(CURDIR))"

ci:
	pipenv run $(MAKE) lint test

deps:
	pipenv install --dev

deps-update:
	pipenv update

global-helpers-unit-test:
	pipenv run python global_helpers/*_test.py

lint: lint-pylint lint-fmt

lint-pylint:
	pipenv run bandit -r $(dirs) --skip B101  # allow assert statements in tests
	pipenv run pylint $(dirs) \
	  --disable=missing-docstring,duplicate-code,import-error,fixme,consider-iterating-dictionary,global-variable-not-assigned \
	  --load-plugins=pylint.extensions.mccabe,pylint_print \
	  --max-line-length=100

lint-fmt:
	@echo Checking python file formatting with the black code style checker
	pipenv run black --line-length=100 --check $(dirs)

venv:
	pipenv install --dev

pat-update:
	pipenv update panther-analysis-tool

fmt:
	pipenv run isort --profile=black $(dirs)
	pipenv run black --line-length=100 $(dirs)

install:
	pipenv install --dev

test: global-helpers-unit-test
	pipenv run panther_analysis_tool test

docker-build:
	docker build -t panther-analysis .

docker-test:
	docker run --mount "type=bind,source=${CURDIR},target=/home/panther-analysis" panther-analysis make test

docker-lint:
	docker run --mount "type=bind,source=${CURDIR},target=/home/panther-analysis" panther-analysis make lint
