FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY web ./web

ENV DATA_DIR=/data
ENV MONITOR_HTTPS=1
ENV MONITOR_COOKIE_SECURE=1
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import os,ssl,urllib.request; https=os.environ.get('MONITOR_HTTPS','1')=='1'; ctx=ssl._create_unverified_context() if https else None; urllib.request.urlopen(('https' if https else 'http')+'://127.0.0.1:8080/api/health', context=ctx)"

CMD ["python", "-m", "app.serve"]
