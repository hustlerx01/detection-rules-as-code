FROM python:3.12-slim
WORKDIR /app
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY . .
CMD ["sh", "-c", "python -m dac.validate && python -m dac.runtests && pytest -q"]
