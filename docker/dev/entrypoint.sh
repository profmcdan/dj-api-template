#!/bin/sh

# python manage.py flush --no-input
python manage.py makemigrations --no-input
python manage.py migrate --no-input
# python manage.py collectstatic --no-input --clear
rm celerybeat.pid

exec "$@"
