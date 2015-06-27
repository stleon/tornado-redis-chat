# tornado-redis-chat
More info [here](http://omgit.ru/blog/tornado-redis-chat/)

## How to run

```
cd tornado-redis-chat
docker build -t chat .
docker run --name some-redis -d redis
docker run --name some-app -p 8888:8888 --link some-redis:redis -d cha
t
```

And then you can go https://192.168.59.103:8888/login (for me)
