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

install:
	pipenv install --dev

test:
	pipenv run panther_analysis_tool test

