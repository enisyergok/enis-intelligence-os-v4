
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bridge ./bridge
ENV PORT=8080
CMD ["sh","-c","uvicorn bridge.app:app --host 0.0.0.0 --port ${PORT}"]
