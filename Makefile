packages = analysis

ci:
	pipenv run $(MAKE) lint unit integration

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	yapf $(packages) --diff --parallel --recursive --style google
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

test:
	panther-cli test --policies $(packages)
