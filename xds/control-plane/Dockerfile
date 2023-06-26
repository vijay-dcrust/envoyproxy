FROM golang:1.20-buster AS builder

# Create working directory under /app
WORKDIR /app
# COPY  --chmod=777 server-cert.pem server-cert.pem
# COPY  --chmod=777 server-key.pem server-key.pem

COPY go.* ./
RUN go mod download
COPY . ./
RUN go build -o /xds_go
ENTRYPOINT ["/xds_go"]