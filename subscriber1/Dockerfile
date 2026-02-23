FROM golang:1.26-alpine

WORKDIR /app

COPY go.mod go.sum ./
COPY utility/ ./utility/

WORKDIR /app/subscriber1
COPY subscriber1/go.mod ./
RUN go mod download
COPY subscriber1/ ./
RUN go build -o subscriber1 .

CMD ["./subscriber1"]