FROM python:3.12-slim

WORKDIR /app

# Copy project into container
COPY . /app

# Make entrypoint script executable
RUN chmod +x /app/docker-entrypoint.sh

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
