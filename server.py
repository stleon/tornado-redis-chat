from tornado.web import RequestHandler, Application, url, StaticFileHandler
from tornado.ioloop import IOLoop
from tornado.websocket import WebSocketHandler
import os
from datetime import datetime
import uuid
import tornadoredis
from tornado import gen, web
from tornado.escape import native_str
import json
import hashlib

HOST = '127.0.0.1'
PORT = 8888
REDIS_PORT = 6379
COOKIE_NAME = 'user'
MAX_MESSAGE_LEN = 255
PROTOCOL_V = 0.1

c = tornadoredis.Client()
c.connect()


def authenticated_async(method):
    @gen.coroutine
    def wrapper(self, *args, **kwargs):
        self._auto_finish = False
        self.current_user = yield gen.Task(self.get_current_user_async)
        if not self.current_user:
            self.redirect(self.reverse_url('login'))
        else:
            result = method(self, *args, **kwargs)
            if result is not None:
                yield result

    return wrapper


class BaseClass():
    @gen.coroutine
    def get_current_user_async(self, ):  #callback
        "Нужно для того, чтобы могли асинхронно делать запросы"

        auth_cookie = native_str(self.get_secure_cookie(COOKIE_NAME,
                                                        max_age_days=3))
        if auth_cookie:  # если юзер вообще залогинен

            user_id = yield gen.Task(c.hget, 'auths', auth_cookie)

            user_auth = yield gen.Task(c.hget, 'user:%s' % user_id, 'auth')
            if auth_cookie != user_auth:
                return None
            else:
                user_name = yield gen.Task(c.hget, 'user:%s' % user_id,
                                           'username')

                return {'id': user_id, 'name': user_name}

        else:
            return None


class LoginHandler(BaseClass, RequestHandler):
    def get(self):
        if not self.get_secure_cookie(COOKIE_NAME, max_age_days=3):
            self.render(
                "login.html",
                error=None
            )  # да, можно потом красиво в блоки завернуть, базовый html и тд

    @staticmethod
    def hash_password(password, salt):
        "Возвращает хэш пароля, так как хранить в открытом виде - опасно. + используем соль"
        password_salt = '%s%s' % (password, salt)
        return hashlib.sha512(password_salt.encode('utf-8')).hexdigest()

    @gen.coroutine
    def post(self):
        # Предполагается, что честно ввели логин/пароль + нет проверки, что куки уже есть и тд
        # check_xsrf_cookie auto
        username = self.get_argument("login").strip()
        password = self.get_argument("password").strip()
        user_id = yield gen.Task(c.hget, 'users', username)

        if not user_id:
            # Юзер еще не регался - зарегаем с таким именем и паролем
            auth_secret = str(uuid.uuid4())
            new_user_id = yield gen.Task(c.incr, 'next_user_id')

            salt = str(uuid.uuid4())

            password = LoginHandler.hash_password(password, salt)

            pipe = c.pipeline()
            pipe.hmset(key='user:%s' % new_user_id,
                       mapping={
                           'username': username,
                           'password': password,
                           'salt': salt,
                           'auth': auth_secret
                       })
            pipe.hset('users', username, new_user_id)
            pipe.hset('auths', auth_secret, new_user_id)
            yield gen.Task(pipe.execute)  # выполнится как одна команда

            self.end_reg_or_login(auth_secret)

        else:
            # юзер есть, теперь проверим пароль - сравним хэши
            user_ps = yield gen.Task(c.hmget,
                                     key='user:%s' % user_id,
                                     fields=('password', 'salt'))
            password = LoginHandler.hash_password(password, user_ps["salt"])

            if password != user_ps["password"]:
                self.render(
                    "login.html",
                    error=
                    'Неправильное имя юзера или пароль. Или юзер с таким логином уже есть')
            else:
                auth_secret = yield gen.Task(c.hget, 'user:%s' % user_id,
                                             "auth")
                self.end_reg_or_login(auth_secret)

    def end_reg_or_login(self, auth_secret):
        "Выставляем куки, перенаправляем на главную"
        self.set_secure_cookie(COOKIE_NAME, auth_secret,
                               domain=HOST,
                               expires_days=3)
        self.redirect(self.reverse_url('index'))


class LogoutHandler(BaseClass, RequestHandler):
    @authenticated_async
    @gen.coroutine
    def get(self):
        "Удаляем старый auth_secret и пишем новый"

        new_auth_secret = str(uuid.uuid4())
        user_id = self.current_user['id']
        old_auth_secret = yield gen.Task(c.hget, 'user:%s' % user_id, "auth")

        pipe = c.pipeline()
        pipe.hset('user:%s' % user_id, 'auth', new_auth_secret)
        pipe.hset('auths', new_auth_secret, user_id)
        pipe.hdel('auths', old_auth_secret)
        yield gen.Task(pipe.execute)

        self.clear_all_cookies()
        self.redirect(self.reverse_url('login'))


class IndexPageHandler(BaseClass, RequestHandler):
    @authenticated_async
    @gen.coroutine
    def get(self):
        self.render("index.html",
                    host=HOST,
                    port=PORT,
                    message_len=MAX_MESSAGE_LEN,
                    protocol_v=PROTOCOL_V)


class ChatHandler(BaseClass, WebSocketHandler):
    @staticmethod
    def get_current_time():
        "текущее время, не учитываем временные зоны"
        return datetime.now().strftime('%H:%M:%S')

    @authenticated_async
    def open(self):
        self.write_message(
            {'type': 'welcome',
             'data': {'protocol_v': PROTOCOL_V}})
        self.listen()

    @authenticated_async
    @gen.coroutine
    def listen(self):
        "Слушаем новые сообщения и по умолчанию сразу подписываемся на общий чат + на его личный канал, в который ему будут приходить входящие"
        self.client = tornadoredis.Client()
        self.client.connect()
        yield gen.Task(
            self.client.subscribe,
            channels=('1', 'user_chanel_%s' % self.current_user['id']))
        yield gen.Task(c.sadd, 'channels:%s' % self.current_user['id'], '1')

        users_channels = yield gen.Task(c.smembers, 'channels:%s' %
                                        self.current_user['id'])
        users_channels = list(users_channels)
        users_channels.sort()
        self.write_message(
            {'type': 'mine_channels',
             'data': {'channels': users_channels}})
        self.client.listen(callback=self.send_messages)

    @gen.coroutine
    def on_message(self, message):
        message = json.loads(
            message
        )  # message - всегда строка - https://developer.mozilla.org/en-US/docs/Web/API/WebSocket#send()
        if message["type"] == 'send_message' and len(message["data"][
            "text"
        ]) <= MAX_MESSAGE_LEN:  # TODO проверка не на символы, а на вес кб
            message["data"].update({
                'author': self.current_user,
                'current_time': ChatHandler.get_current_time()
            })  # добавляем автора и время
            yield gen.Task(c.publish,
                           message=json.dumps(message),
                           channel=message["data"]["channel_id"]
                  )  # публиковать можно только строку

        if message["type"] == 'join' and message["data"][
            "channel_id"
        ]:  # юзер хочет подписаться на канал
            # TODO сделать одной командой Pipelines
            yield gen.Task(c.sadd, 'channels:%s' % self.current_user['id'],
                           message["data"]["channel_id"])
            yield gen.Task(self.client.subscribe,
                           message["data"]["channel_id"])

            self.write_message({
                'type': 'success_join',
                'data': {'channel_id': message["data"]["channel_id"]}
            })

        if message["type"] == 'unjoin' and message["data"][
            "channel_id"
        ]:  # если юзер хочет отписаться от канала
            yield gen.Task(c.srem, 'channels:%s' % self.current_user['id'],
                           message["data"]["channel_id"]
                  )  # удаляем канал из множества каналов юзера
            yield gen.Task(
                self.client.unsubscribe, str(message["data"]["channel_id"])
            )  # если не строка, то будет error
            self.write_message({
                'type': 'success_unjoin',
                'data': {'channel_id': message["data"]["channel_id"]}
            })

        if message["type"] == "send_private_message" and message["data"][
            "to_user"
        ] and len(message["data"][
            "text"
        ]) <= MAX_MESSAGE_LEN:  # TODO проверка не на символы, а на вес кб
            message["data"].update({'author': self.current_user})
            user_id = yield gen.Task(c.hget, 'users',
                                     message["data"]["to_user"])
            yield gen.Task(c.publish,
                           message=json.dumps(message),
                           channel='user_chanel_%s' % user_id
                  )  # пишем в канал указанного юзера

    def send_messages(self, msg, ):  #author='System'
        "Рассылаем сообщения"

        if msg.kind == 'message':
            message = json.loads(msg.body)
            if message['data']['author']['id'] != self.current_user[
                'id'
            ]:  # автору не присылается
                self.write_message(msg.body
                       )  # отдаем строку, в json преобразуем на клиенте
        elif msg.kind == 'disconnect':
            message = json.loads(msg.body)
            message.update({'author': 'System', 'text': 'Ошибка в R...', })
            self.write_message(json.dumps(message))
            self.close()

    @gen.coroutine
    def on_close(self):
        "При отсоединении - можно юзать self.client.subscribed, но он вернет только список с железа, на котором работает"

        #users_channels = yield gen.Task(c.smembers, 'channels:{}'.format(self.current_user['id']))
        #yield gen.Task(self.client.unsubscribe, users_channels)
        #yield gen.Task(c.srem, 'channels:{}'.format(self.current_user['id']), users_channels) # не сработает

        yield gen.Task(self.client.disconnect)

    def check_origin(self, origin):
        return True


def make_app():

    settings = {
        'login_url': "/login",
        'compress_response': True,
        'template_path': os.path.join(os.path.dirname(__file__), "templates"),
        'static_path': os.path.join(os.path.dirname(__file__), "static"),
        'cookie_secret': "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
        'xsrf_cookies': True,
        'debug': False,
    }

    return Application(handlers=[
        url(r"/", IndexPageHandler,
            name='index'),
        url(r"/login", LoginHandler,
            name='login'),
        url(r"/logout", LogoutHandler),
        url(r"/websocket", ChatHandler),
        (r'/(favicon\.ico)', StaticFileHandler, dict(path=
                                                     settings['static_path'])),
    ], **settings)


if __name__ == '__main__':
    app = make_app()
    app.listen(PORT,
               ssl_options={
                   "certfile": os.path.join(os.path.dirname(__file__),
                                            "localhost.crt"),
                   "keyfile": os.path.join(os.path.dirname(__file__),
                                           "localhost.key"),
               })
    IOLoop.current().start()
