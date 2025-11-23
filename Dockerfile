# Dockerfile
FROM python:3.11-slim AS builder
WORKDIR /app
COPY pyproject.toml requirements.txt /app/
RUN pip install --upgrade pip
RUN pip wheel --wheel-dir /wheels -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels -r requirements.txt
COPY . /app
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
