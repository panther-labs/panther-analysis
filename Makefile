packages = panther_cli analysis

ci:
	pipenv run $(MAKE) lint unit integration

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	yapf $(packages) --diff --parallel --recursive --style google
	mypy panther_cli --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores || true # TODO(jack) Figure out why mypy is failinig on 'has no attribute' error
	bandit -r $(packages)
	pylint $(packages) --disable=missing-docstring,bad-continuation,duplicate-code,W0511 --exit-zero

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run yapf $(packages) --in-place --recursive --parallel --style google

install:
	pip3 install --user --upgrade pip
	pip3 install pipenv --upgrade
	pipenv install

unit:
	pipenv run nosetests -v

integration:
	panther-cli test --policies tests/fixtures/valid_policies/
