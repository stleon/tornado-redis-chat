FROM python:3.4.3-slim

MAINTAINER LEON ST <leonst998@gmail.com>
RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY static/favicon.ico /usr/src/app/static/favicon.ico
COPY templates/index.html /usr/src/app/templates/index.html
COPY templates/login.html /usr/src/app/templates/login.html
COPY server.py /usr/src/app/
COPY requirements.txt /usr/src/app/

RUN openssl req -new -newkey rsa:2048 -nodes -out localhost.csr -keyout localhost.key -subj "/C=RU/ST=/L=/O=/CN=localhost"
RUN openssl x509 -req -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt

RUN pip install -r requirements.txt

CMD [ "python", "./server.py" ]

EXPOSE 8888
