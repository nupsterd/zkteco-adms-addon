ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache python3 py3-pip

WORKDIR /app
COPY zkteco_adms/ /app/
RUN pip3 install aiohttp --break-system-packages

CMD ["python3", "/app/server.py"]
