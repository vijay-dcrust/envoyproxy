# envoyproxy

## Run a go server first //echo is a simple tcp server to echo the given data
```
cd server
docker build -t hello_go_http .
docker run -p 8080:8080 -t hello_go_http --rm
curl http://localhost:8080 -d hii
```

## Run the envoy proxy in another container
```
cd proxy
docker build -t envoy:v2 .
docker run -d --name envoy -p 9901:9901 -p 10000:10000 envoy:v2
curl http://localhost:10000 -d hii
```

Above processes can be simply run without docker also as mentioned in the readme in folder xds/
