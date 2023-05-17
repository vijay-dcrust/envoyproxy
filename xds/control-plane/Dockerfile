FROM golang:1.20-buster AS builder

# Create working directory under /app
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY xds.go ./
RUN go build -o /xds_go
ENTRYPOINT ["/xds_go"]