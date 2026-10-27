# Build context = repository root (docker-compose.yml), so the frozen contracts/ can be copied for schema checks.
FROM python:3.11-slim
WORKDIR /app
COPY core/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY core/app ./app
COPY core/devtools ./devtools
COPY contracts ./contracts
EXPOSE 8000
# no access log: request paths can carry receipt hashes (README "PII": logs never contain them)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
