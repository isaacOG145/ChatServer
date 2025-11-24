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

Se implementa un modulo para verificar las firmas digitales de los documentos, inicio de sesion con google y se hace uso de tailwind para el diseño 

7a045461a45210f225f0c313aec029f4  app.py
95ca88183433edbef97dc2c9088f3408  jwt_utils.py
919407fa44d47db124890ffbeeaecd27  package.json
0a7cb4321928779f461d6d47e16a6ee6  crypto_utils.py
c54cd212184d49a1d08e012eb997bdb3  requirements.txt
7732016d24dc5a764a0ac6555d7bf326  package-lock.json
9ae5ea09951102dcb8b58a1c8b7111aa  ./templates/manual_signature.html
349120d718664237a49ecbde294c6a25  ./templates/oauthLogin.html
458f08a5b108f7d8cd29b2c1beef207f  ./templates/room.html
7b5df4d44a64d62b85335888b8313307  ./static/css/output.css
7ebb8b559f2c4b96e188524305cef746  ./static/css/input.css
eac10fd312145b185bac4e5eae0775c0  ./static/js/toggle.js

