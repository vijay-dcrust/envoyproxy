FROM envoyproxy/envoy:tools-dev
COPY envoy.yml /etc/envoy/envoy.yaml
COPY  --chmod=777 myca.key /etc/myca.key
COPY  --chmod=777 myca.crt /etc/myca.crt
COPY  --chmod=777 server-cert.pem /etc/server-cert.pem
COPY  --chmod=777 server-key.pem /etc/server-key.pem
