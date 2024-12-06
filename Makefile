dirs := $(shell ls | egrep 'policies|rules|global_helpers|models|templates|queries' | xargs)
UNAME := $(shell uname)
TEST_ARGS :=

ifeq ($(UNAME), Darwin)
	install_pipenv_cmd = brew install pipenv
endif

install-pipenv:
	which pipenv || $(install_pipenv_cmd)

vscode-config: install-pipenv install
	@echo "backing up existing vscode configs"
	test -f .vscode/settings.json && cp .vscode/settings.json .vscode/settings_bak.json \
	   || echo "no existing vscode settings.json file found. continuing"
	test -f .vscode/launch.json && cp .vscode/launch.json .vscode/launch_bak.json \
	   || echo "no existing vscode launch.json file found. continuing"
	@echo "Creating new vscode config files"
	cp .vscode/example_launch.json  .vscode/launch.json
	sed -e 's#XXX_pipenv_py_output_XXX#$(shell pipenv --py)#' .vscode/example_settings.json  > .vscode/settings.json
	which code && code .

ci:
	pipenv run $(MAKE) lint test

deps:
	pipenv sync --dev

deps-update:
	pipenv update

global-helpers-unit-test:
	pipenv run python -m unittest global_helpers/*_test.py

data-models-unit-test:
	pipenv run python -m unittest data_models/*_test.py

lint: lint-pylint lint-fmt

lint-pylint:
	pipenv run bandit -r $(dirs)
	pipenv run pylint $(dirs)
	pipenv run isort --profile=black --check-only $(dirs)

lint-fmt:
	@echo Checking python file formatting with the black code style checker
	pipenv run black --line-length=100 --check $(dirs)

lint-mitre:
	pipenv run python3 ./.scripts/mitre_mapping_check.py

venv:
	pipenv sync --dev

pat-update:
	pipenv update panther-analysis-tool

fmt:
	pipenv run isort --profile=black $(dirs)
	pipenv run black --line-length=100 $(dirs)

install:
	pipenv sync --dev

test: global-helpers-unit-test data-models-unit-test
	pipenv run panther_analysis_tool test $(TEST_ARGS)

check-deprecated:
	pipenv run python3 ./.scripts/deleted_rules.py check

remove-deprecated:
	pipenv run python3 ./.scripts/deleted_rules.py remove

docker-build:
	docker build -t panther-analysis:latest .

docker-test:
	docker run --mount "type=bind,source=${CURDIR},target=/home/panther-analysis" panther-analysis:latest make test TEST_ARGS="$(TEST_ARGS)"

docker-lint:
	docker run --mount "type=bind,source=${CURDIR},target=/home/panther-analysis" panther-analysis:latest make lint
