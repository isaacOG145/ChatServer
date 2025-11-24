chat version 1.0 

chat basico con socketio y flask 

MD5:
26f7a9686a99cf781831e43bb590df74  app.py
de4b38febcb8230030512d1b6ed4b068  requirements.txt
91ef1f58fa8ca50e094329b5eb989ab6  templates/chat.html
35ce96919a8b71ecd2e9112d1f627eb4  templates/login.html

chat version 1.1

chat simetrico con hash basico,a los mensajes se les aplica un hash usando una llave unica

f662fdbe0d31d997d54425185f581628 app.py
69ac34c378f6ec34b2913add72ff8483 requirements.txt
0ddbb5264d04bed9a6b71b7864622bef crypto_utils.py
b053008b8db973f9f4b36976de4be79e templates/index.html
82177d78c3b0eb8fea26d4a5352da323 templates/chat.html 
35ce96919a8b71ecd2e9112d1f627eb4 templates/login.html

chat version 1.1.1

chat asimetrico con hash basico, a los mensajes se les aplica un hash usando una llave publica y 
una llave privada 

1c4e217a31856204db6e167a318543b0  requirements.txt
85c416a29a5d878cf02b0473e862d245  app.py
0d3585b9a727ace36b7341d5fee38bfb  crypto_utils.py
b053008b8db973f9f4b36976de4be79e  ./templates/index.html
be7be3619fac94f94d7592b6eeadce05  ./templates/chat.html
35ce96919a8b71ecd2e9112d1f627eb4  ./templates/login.html

chat version 1.2

chat con hash simetrico + sha256, se calcula el hash con el sha256 para confirmar la autenticidad

7ba5bc3cbd8d34432d5e5ac85fc7083b app.py
69ac34c378f6ec34b2913add72ff8483 requirements.txt
0ddbb5264d04bed9a6b71b7864622bef crypto_utils.py
b053008b8db973f9f4b36976de4be79e templates/index.html
44d87349e9085a5c1de6f4043adbf445 templates/chat.html
35ce96919a8b71ecd2e9112d1f627eb4 templates/login.html

chat version 1.2.1

chat asimetrico con hash + sha256, se calcula el hash con el sha256 para confirmar la autenticidad

2687c8d90a9ed36f17994d9dd01aa20b  app.py
0d3585b9a727ace36b7341d5fee38bfb  crypto_utils.py
1c4e217a31856204db6e167a318543b0  requirements.txt
b053008b8db973f9f4b36976de4be79e  ./templates/index.html
35ce96919a8b71ecd2e9112d1f627eb4  ./templates/login.html
5ffb067c1bf4cbb7d4954377386f7b6b  ./templates/chat.html

chat version 1.3

Se aplican variables de entorno en un .env y se trabajo con la version asimetrica

3a9a550d3434d17ac88ce2c14c71110e  app.py
5132377d863fa34f2c1e40c9f077b15e  requirements.txt
ce193e5868f140ed9ced42745f24f8cf  crypto_utils.py
4b176231bf8432c78e11f33e50025e7c  ./templates/login.html
1964cb8dff9c4a92f4687983a7878afa  ./templates/chat.html

chat version 1.4



