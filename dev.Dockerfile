FROM python:3.10-slim

RUN mkdir -p /app/storage && ln -s /storage /app/storage # backward compability for (https://github.com/CatchTheTornado/text-extract-api/issues/85)

RUN echo 'Acquire::http::Pipeline-Depth 0;\nAcquire::http::No-Cache true;\nAcquire::BrokenProxy true;\n' > /etc/apt/apt.conf.d/99fixbadproxy

RUN apt-get clean && rm -rf /var/lib/apt/lists/* \
    && apt-get update --fix-missing \
    && apt-get install -y \
        libglib2.0-0 \
        libglib2.0-dev \
        libgl1 \
        poppler-utils \
        libmagic1 \
        libmagic-dev \
        libpoppler-cpp-dev \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /app

# Copia todos os arquivos do projeto para o container
COPY . /app

# Instala as dependências Python
RUN python -m venv .dvenv && \
    . .dvenv/bin/activate && \
    pip install --upgrade pip setuptools && \
    pip install .

EXPOSE 2323

ENTRYPOINT ["/app/scripts/entrypoint.sh"]