import time
from datetime import datetime

from django.conf import settings
from django.core.files import File
from django.core.mail import EmailMultiAlternatives


def send_email(subject, email_from, html_alternative, text_alternative):
    msg = EmailMultiAlternatives(
        subject, text_alternative, settings.EMAIL_FROM, [email_from])
    msg.attach_alternative(html_alternative, "text/html")
    msg.send(fail_silently=False)


def generate_user_temp_id():
    now_tm = (datetime.now().strftime('%Y%m%d%H%M%S'))
    time_array = time.strptime(now_tm, '%Y%m%d%H%M%S')
    stamp_tm = int(time.mktime(time_array))
    return "NG" + str(hex(stamp_tm)[2:]).upper()


async def create_file_from_image(url):
    return File(open(url, 'rb'))
