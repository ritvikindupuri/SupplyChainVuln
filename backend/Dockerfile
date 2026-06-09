FROM python:3.11-slim

# Non-root user for isolation
RUN useradd --create-home --uid 10001 coreuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Reports dir is backed by a writable volume; ensure ownership
RUN mkdir -p /app/reports && chown -R coreuser:coreuser /app

USER coreuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
