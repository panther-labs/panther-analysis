analysis_directories = aws_policies_cis aws_policies_managed aws_policies_s3 aws_rules_cis aws_rules_cloudtrail aws_rules_guardduty aws_rules_s3_access_logs aws_rules_vpc_flow_logs globals osquery_rules

ci:
	pipenv run $(MAKE) lint test

deps:
	pip3 install -r requirements.txt

deps-update:
	pip3 install -r requirements-top-level.txt --upgrade
	pip3 freeze -r requirements-top-level.txt > requirements.txt

lint:
	yapf $(analysis_directories) --diff --parallel --recursive --style google
	bandit -r $(analysis_directories)
	pylint $(analysis_directories) --disable=missing-docstring,bad-continuation,duplicate-code,W0511 --exit-zero

venv:
	virtualenv -p python3.7 venv

fmt:
	pipenv run yapf $(analysis_directories) --in-place --recursive --parallel --style google

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
	cp -r globals "$$tmp"; \
	cp -r $(pack) "$$tmp"; \
	panther_analysis_tool test --path "$$tmp"; \
	rm -r "$$tmp";
