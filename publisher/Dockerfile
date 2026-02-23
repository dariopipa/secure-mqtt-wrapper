FROM golang:1.26-alpine

WORKDIR /app

COPY go.mod go.sum ./
COPY utility/ ./utility/

WORKDIR /app/publisher
COPY publisher/go.mod ./
RUN go mod download
COPY publisher/ ./
RUN go build -o publisher .

CMD ["./publisher"]