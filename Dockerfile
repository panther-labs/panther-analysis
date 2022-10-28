FROM python:3.9-slim

# Install Make to use make commands inside container
RUN apt-get update
RUN apt-get install -y --no-install-recommends make

# Install pipenv
RUN pip install --upgrade pip
RUN pip install pipenv

# Swithc working directories
WORKDIR /home/panther-analysis

# Install requirements
COPY Pipfile .
COPY Pipfile.lock .
RUN pipenv uninstall --all
RUN pipenv sync --dev

# Remove pipfile so it doesn't interfere with local files after install
RUN rm Pipfile 
RUN rm Pipfile.lock
