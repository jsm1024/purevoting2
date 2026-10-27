FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PUREVOTING_REFERENCE_ROOT=/reference
WORKDIR /app/rules
COPY requirements-lock.txt ./requirements-lock.txt
RUN pip install --no-cache-dir -r requirements-lock.txt
COPY . ./
ENTRYPOINT ["python", "run_simulation.py"]
CMD ["--output", "/output"]
