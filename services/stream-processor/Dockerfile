FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    kafka-python==2.0.2 \
    redis==5.0.1 \
    psycopg2-binary==2.9.9 \
    elasticsearch==8.11.0

COPY processor.py .

CMD ["python", "-u", "processor.py"]
