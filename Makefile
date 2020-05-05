# How to get this list: ls | egrep 'policies|rules|global_helpers' | xargs | pbcopy
analysis_directories = aws_account_policies aws_acm_policies aws_cloudtrail_policies aws_cloudtrail_rules aws_config_policies aws_dynamodb_policies aws_ec2_policies aws_elb_policies aws_guardduty_policies aws_guardduty_rules aws_iam_policies aws_kms_policies aws_rds_policies aws_redshift_policies aws_s3_policies aws_s3_rules aws_vpc_policies aws_vpc_rules aws_waf_policies global_helpers osquery_rules

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
	cp -r global_helpers "$$tmp"; \
	cp -r $(pack) "$$tmp"; \
	panther_analysis_tool test --path "$$tmp"; \
	rm -r "$$tmp";
