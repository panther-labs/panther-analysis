analysis_directories := $(shell ls | egrep 'policies|rules|helpers|models' | xargs)

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
	panther_analysis_tool test 
