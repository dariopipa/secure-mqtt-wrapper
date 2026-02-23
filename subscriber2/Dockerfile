FROM golang:1.26-alpine

WORKDIR /app

COPY go.mod go.sum ./
COPY utility/ ./utility/

WORKDIR /app/subscriber2
COPY subscriber2/go.mod ./
RUN go mod download

COPY subscriber2/ ./
RUN go build -o subscriber2 .

CMD ["./subscriber2"]