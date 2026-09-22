FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    API_PORT=8080

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY acceptance ./acceptance

EXPOSE 8080

# single process, threaded WSGI (waitress); state lives on the shared volume
CMD ["python", "-m", "app.api"]
