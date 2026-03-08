FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/src
COPY src/__init__.py ./src/__init__.py
COPY src/app.py ./src/app.py
COPY src/detection_engine.py ./src/detection_engine.py
COPY data ./data

EXPOSE 8000
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
