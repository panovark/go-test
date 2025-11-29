# Этап сборки
FROM --platform=linux/amd64 golang:1.21-alpine AS builder

WORKDIR /app

# Копируем go.mod (если есть) или просто исходники
COPY main.go .

# Собираем бинарник
# CGO_ENABLED=0 делает его полностью статическим (без зависимостей от системных библиотек)
RUN go build -o galactic-exchange main.go

# Финальный этап (минимальный образ)
FROM --platform=linux/amd64 alpine:latest

WORKDIR /root/

COPY --from=builder /app/galactic-exchange .

# Порт, указанный в задании
EXPOSE 8080

# Ограничения ресурсов в Dockerfile не задаются (они задаются при docker run/k8s), 
# но приложение оптимизировано под указанные лимиты.

CMD ["./galactic-exchange"]