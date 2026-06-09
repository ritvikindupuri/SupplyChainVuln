FROM python:3.11-slim

# Run as a non-root user for isolation
RUN useradd --create-home --uid 10001 aiuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY consensus.py .
COPY service.py .

USER aiuser

EXPOSE 9100

CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "9100"]
