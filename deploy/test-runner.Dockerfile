FROM python:3.12-slim

# Java 21 for PySpark, libpq for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-21-jre-headless \
        libpq-dev \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64

WORKDIR /app

# Copy project and install deps
COPY pyproject.toml .
COPY src/ src/
COPY tests/ tests/
COPY notebooks/ notebooks/
COPY deploy/download-spark-connector.sh deploy/download-spark-connector.sh

RUN pip install --no-cache-dir -e '.[dev]'

# Download Iceberg Spark runtime JARs
RUN mkdir -p jars && bash deploy/download-spark-connector.sh || true

ENTRYPOINT ["python", "-m", "pytest"]
CMD ["tests/", "-v", "--tb=short"]
