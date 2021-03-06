#flask
FLASK_APP=run
FLASK_RUN_PORT=5002
FLASK_ENV=development

VAGRANT_IP=192.168.10.11

#mysql
MYSQL_USER=root
MYSQL_PASSWORD=root
MYSQL_HOST=${VAGRANT_IP}
MYSQL_PORT=3306
DB_NAME=benwaonlineauth

#redis
REDIS_HOST=${VAGRANT_IP}
REDIS_PORT=6379

# benwaonline-auth
SECRET_KEY_AUTH=vsecret
PRIVATE_KEY=benwaauth_priv.pem
PUBLIC_KEY=benwaauth_pub.pem
AUTH_HOST=http://127.0.0.1
AUTH_PORT=5002
