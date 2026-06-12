FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN mkdir -p uploads

ENV PORT=8080
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "server.py"]
