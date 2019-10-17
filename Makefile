packages = panther_cli

ci:
	pipenv run $(MAKE) lint unit integration

deps:
	pip install -r requirements.txt

deps-update:
	pip install --upgrade –r requirements-top-level.txt
	pip freeze –r requirements-top-level.txt > requirements.txt

lint:
	yapf $(packages) --diff --parallel --recursive --style google
	mypy panther_cli --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores || true # TODO(jack) Figure out why mypy is failinig on 'has no attribute' error
	bandit -r $(packages)
	pylint $(packages) --disable=missing-docstring,bad-continuation,duplicate-code --exit-zero

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run yapf $(packages) --in-place --recursive --parallel --style google

install:
	pip3 install --upgrade pip
	pip3 install pipenv --upgrade
	pipenv install

unit:
	nosetests -v

integration:
	panther-cli test --policies tests/fixtures/valid_policies/
