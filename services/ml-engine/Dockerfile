FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    redis==5.0.1 \
    psycopg2-binary==2.9.9 \
    scikit-learn==1.3.2 \
    numpy==1.26.2

COPY ml_engine.py .

CMD ["python", "-u", "ml_engine.py"]
