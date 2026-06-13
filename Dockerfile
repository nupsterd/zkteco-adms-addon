FROM ghcr.io/home-assistant/base-python:3.12-alpine3.21

# Zona horaria del container
ENV TZ=America/Bogota

RUN apk add --no-cache openssl tzdata && \
    cp /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    pip3 install aiohttp

WORKDIR /app
COPY zkteco_adms/ /app/
CMD ["python3", "/app/server.py"]