FROM python:3.9-slim

WORKDIR /app

# Run as non-root user for security
RUN useradd -m vulnpilot
RUN chown -R vulnpilot:vulnpilot /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install -e .

USER vulnpilot

EXPOSE 8000
CMD ["vulnpilot", "serve"]
