FROM python:3.12-slim

# security hygiene: run as an unprivileged user, no build tools in the image
RUN useradd --create-home appuser
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

USER appuser
EXPOSE 8000

# Render injects PORT; default to 8000 for local docker run
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
