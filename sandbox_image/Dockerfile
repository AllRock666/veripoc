FROM python:3.12-slim
RUN pip install --no-cache-dir requests
RUN useradd -m runner
USER runner
WORKDIR /work
