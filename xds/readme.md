# How to run control plane
## Run two test microservices

```
cd server
go run server.go

#test
curl curl http://localhost:8080
curl curl http://localhost:8081
```

## Run envoy proxy
```
cd proxy
envoy -c envoy.yml

# test
curl http://localhost:10000
```


## Run xds control plane

```
cd control-plane
go run xds.go
```

## Test blue green by adjusting weight in control-plane console
```
while true; do hey -n 100 -c 5 -t 1  http://localhost:10000/ ; sleep 1;done
```
