FROM ghcr.io/home-assistant/base-python:3.12-alpine3.21

RUN pip3 install aiohttp

WORKDIR /app
COPY zkteco_adms/ /app/

CMD ["python3", "/app/server.py"]
