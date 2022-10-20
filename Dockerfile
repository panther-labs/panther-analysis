FROM python:3.9-slim

# Install Make to use make commands inside container
RUN apt-get update
RUN apt-get install -y --no-install-recommends make

# Install pipenv
RUN pip install --upgrade pip
RUN pip install pipenv

# Swithc working directories
WORKDIR /home/panther-user

# Install requirements
COPY Pipfile .
RUN pipenv uninstall --all --skip-lock
RUN pipenv install --dev --skip-lock

# Copy current repository into container
COPY . . 
