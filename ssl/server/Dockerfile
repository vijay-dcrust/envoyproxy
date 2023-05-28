FROM golang:1.20-buster AS builder

# Create working directory under /app
WORKDIR /app
COPY  --chmod=777 domain.crt domain.crt
COPY  --chmod=777 domain.key domain.key

COPY go.* ./
RUN go mod init temp
COPY server.go ./
RUN go build -o /hello_go_http
ENTRYPOINT ["/hello_go_http"]