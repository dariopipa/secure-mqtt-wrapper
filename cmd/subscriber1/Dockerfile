FROM golang:1.26-alpine

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o subscriber1 ./cmd/subscriber1

CMD ["./subscriber1"]