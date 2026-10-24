FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY seere_sdk ./seere_sdk
COPY seere_mcp ./seere_mcp
RUN pip install --no-cache-dir . && useradd --uid 10001 --create-home seere
USER 10001:10001
ENTRYPOINT ["python", "-m", "seere_sdk.workers"]
