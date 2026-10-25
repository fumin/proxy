# Proxy

## Deploy

```
go build ./cmd/server
mv server $GOPATH/bin/proxy
kill $(lsof -t -i TCP:443 -s TCP:LISTEN)
/home/ec2-user/.local/go/bin/proxy > /home/ec2-user/var/proxy/log 2>&1 &
```
