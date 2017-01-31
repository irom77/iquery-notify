docker stop logstash-prod
docker rm logstash-prod
go get -u github.com/irom77/iquery-notify
cp $GOPATH/bin/iquery-notify exec/
docker build -t prod-logstash .
docker run -d --network influx -p 11514:11514/udp -p 11666:11666 -v $PWD/opt:/opt -v /etc/localtime:/etc/localtime:ro --name logstash-prod prod-logstash