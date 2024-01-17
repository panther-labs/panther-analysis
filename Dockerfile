FROM --platform=$TARGETPLATFORM cgr.dev/chainguard/wolfi-base

ARG TARGETPLATFORM
ARG PYTHON_VERSION="3.9.18"

RUN apk update \
    && apk add --no-cache \
        bash \
        build-base \
        bzip2-dev \
        git \
        libffi-dev \
        openssl-dev \
        readline-dev \
        sqlite-dev \
        tk-dev \
        wget \
        xz-dev \
        zlib \
        zlib-dev

# Install pyenv
RUN git clone https://github.com/pyenv/pyenv.git ~/.pyenv \
    && cd ~/.pyenv && src/configure && make -C src \
    && for path in "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile"; do \
        echo 'export PYENV_ROOT="$HOME/.pyenv"' >> "$path"; \
        echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> "$path"; \
        echo 'eval "$(pyenv init -)"' >> "$path"; \
    done
ENV PATH="/root/.pyenv/bin:$PATH"
ENV PATH="/root/.pyenv/shims:$PATH"

# Install Python
RUN env PYTHON_CONFIGURE_OPTS='--enable-optimizations --with-lto' PYTHON_CFLAGS='-march=native -mtune=native' pyenv install $PYTHON_VERSION \
    && pyenv global $PYTHON_VERSION

# Install pipenv
RUN pip install --upgrade pip
RUN pip install pipenv

WORKDIR /home/panther-analysis

# Install requirements
COPY Pipfile .
COPY Pipfile.lock .
RUN pipenv uninstall --all
RUN pipenv sync --dev

# Remove pipfile so it doesn't interfere with local files after install
RUN rm Pipfile 
RUN rm Pipfile.lock
