FROM python:3.4

MAINTAINER LEON ST <leonst998@gmail.com>
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

RUN openssl req -new -newkey rsa:2048 -nodes -out localhost.csr -keyout localhost.key -subj "/C=RU/ST=/L=/O=/CN=localhost"`
RUN openssl x509 -req -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt

RUN pip install tornado
RUN pip install tornado-redis
CMD [ "python", "./server.py" ]

EXPOSE 8888