FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    redis==5.0.1 \
    psycopg2-binary==2.9.9 \
    elasticsearch==8.11.0 \
    pyjwt==2.8.0 \
    python-jose[cryptography]==3.3.0 \
    passlib[bcrypt]==1.7.4 \
    python-multipart==0.0.6

COPY api.py .

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
