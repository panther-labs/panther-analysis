dirs := $(shell ls | grep -E 'policies|rules|global_helpers|models|templates|queries' | xargs)
UNAME := $(shell uname)
TEST_ARGS :=

ifeq ($(UNAME), Darwin)
	install_pipenv_cmd = brew install pipenv
endif

## help: Show this help message
help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: help

## install-pipenv: Install pipenv using brew if not already installed
install-pipenv: ## Install pipenv using brew if not already installed
	which pipenv || $(install_pipenv_cmd)

## vscode-config: Configure VSCode settings and launch configurations for this project
vscode-config: install-pipenv install ## Configure VSCode settings and launch configurations for this project
	@echo "backing up existing vscode configs"
	test -f .vscode/settings.json && cp .vscode/settings.json .vscode/settings_bak.json \
	   || echo "no existing vscode settings.json file found. continuing"
	test -f .vscode/launch.json && cp .vscode/launch.json .vscode/launch_bak.json \
	   || echo "no existing vscode launch.json file found. continuing"
	@echo "Creating new vscode config files"
	cp .vscode/example_launch.json  .vscode/launch.json
	sed -e 's#XXX_pipenv_py_output_XXX#$(shell pipenv --py)#' .vscode/example_settings.json  > .vscode/settings.json
	which code && code .

## ci: Run linters and tests (suitable for CI environments)
ci: ## Run linters and tests (suitable for CI environments)
	pipenv run $(MAKE) lint test

## deps: Sync dependencies from Pipfile.lock
deps: ## Sync dependencies from Pipfile.lock
	pipenv sync --dev

## deps-update: Update dependencies in Pipfile.lock
deps-update: ## Update dependencies in Pipfile.lock
	pipenv update

## global-helpers-unit-test: Run unit tests for global helpers
global-helpers-unit-test: ## Run unit tests for global helpers
	pipenv run python -m unittest global_helpers/*_test.py

## data-models-unit-test: Run unit tests for data models
data-models-unit-test: ## Run unit tests for data models
	pipenv run python -m unittest data_models/*_test.py

## lint: Run all linters (pylint, bandit, isort, black checks)
lint: lint-pylint lint-fmt ## Run all linters (pylint, bandit, isort, black checks)

## lint-pylint: Run pylint, bandit, and isort checks
lint-pylint: ## Run pylint, bandit, and isort checks
	pipenv run bandit -r $(dirs)
	pipenv run pylint $(dirs)
	pipenv run isort --profile=black --check-only $(dirs)

## lint-fmt: Check code formatting using black
lint-fmt: ## Check code formatting using black
	@echo Checking python file formatting with the black code style checker
	pipenv run black --line-length=100 --check $(dirs)

## lint-mitre: Run MITRE mapping check script
lint-mitre: ## Run MITRE mapping check script
	pipenv run python3 ./.scripts/mitre_mapping_check.py

## venv: Sync dependencies (alias for deps)
venv: ## Sync dependencies (alias for deps)
	pipenv sync --dev

## pat-update: Update the panther-analysis-tool dependency
pat-update: ## Update the panther-analysis-tool dependency
	pipenv update panther-analysis-tool

## fmt: Format code using isort and black
fmt: ## Format code using isort and black
	pipenv run isort --profile=black $(dirs)
	pipenv run black --line-length=100 $(dirs)

## run-pre-commit-hooks: Run pre-commit hooks on all files
run-pre-commit-hooks: ## Run pre-commit hooks on all files
	@echo "Running pre-commit hooks on all files..."
	pipenv run pre-commit run --all-files

## install: Install all project dependencies (dev included)
install: ## Install all project dependencies (dev included)
	pipenv sync --dev

## install-pre-commit-hooks: Install pre-commit hooks into .git/hooks
install-pre-commit-hooks: ## Install pre-commit hooks into .git/hooks
	pipenv run pre-commit install

## test: Run unit tests and panther_analysis_tool tests
test: global-helpers-unit-test data-models-unit-test ## Run unit tests and panther_analysis_tool tests
	pipenv run panther_analysis_tool test $(TEST_ARGS)

# Used by Panther team to update deprecated.txt
## check-deprecated: Check for deprecated rules (internal use)
check-deprecated: ## Check for deprecated rules (internal use)
	pipenv run python3 ./.scripts/deleted_rules.py check

# Used by Panther customers to delete detection content in deprecated.txt from their Panther instance
## remove-deprecated: Remove deprecated rules from Panther instance (customer use)
remove-deprecated: ## Remove deprecated rules from Panther instance (customer use)
	pipenv run python3 ./.scripts/deleted_rules.py remove

## docker-build: Build the Docker image for panther-analysis
docker-build: ## Build the Docker image for panther-analysis
	docker build -t panther-analysis:latest .

## docker-test: Run tests within the Docker container
docker-test: ## Run tests within the Docker container
	docker run --mount "type=bind,source=${CURDIR},target=/home/panther-analysis" panther-analysis:latest make test TEST_ARGS="$(TEST_ARGS)"

## docker-lint: Run linters within the Docker container
docker-lint: ## Run linters within the Docker container
	docker run --mount "type=bind,source=${CURDIR},target=/home/panther-analysis" panther-analysis:latest make lint

.PHONY: help install-pipenv vscode-config ci deps deps-update global-helpers-unit-test data-models-unit-test lint lint-pylint lint-fmt lint-mitre venv pat-update fmt run-pre-commit-hooks install install-pre-commit-hooks test check-deprecated remove-deprecated docker-build docker-test docker-lint

.PHONY: generate-versions
generate-versions: ## Generate versions file
	pipenv run python3 .scripts/generate_versions_file.py

.PHONY: test-generate-versions
test-generate-versions: ## Test generate versions file
	pipenv run python3 -m pytest .scripts/test_generate_versions_file.py