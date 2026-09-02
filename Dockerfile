FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY photo2seed.py ripemd160.py english.txt ./
ENTRYPOINT ["python", "/app/photo2seed.py"]