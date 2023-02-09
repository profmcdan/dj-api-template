# Generated by Django 4.1.6 on 2023-02-09 12:48

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('password', models.CharField(max_length=255, null=True)),
                ('firstname', models.CharField(max_length=255, null=True)),
                ('middle_name', models.CharField(blank=True, max_length=255, null=True)),
                ('lastname', models.CharField(max_length=255, null=True)),
                ('image', models.FileField(blank=True, null=True, upload_to='users/')),
                ('phone', models.CharField(blank=True, max_length=17, null=True)),
                ('role', models.CharField(choices=[('SUPERADMIN', 'SUPERADMIN'), ('ADMIN', 'ADMIN'), ('CANDIDATE', 'CANDIDATE')], max_length=50)),
                ('user_ref', models.CharField(max_length=50, null=True)),
                ('is_active', models.BooleanField(default=False)),
                ('last_login', models.DateTimeField(null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('verified', models.BooleanField(default=False)),
                ('is_deleted', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'ordering': ('-created_at',),
            },
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('token', models.CharField(max_length=255, null=True)),
                ('token_type', models.CharField(choices=[('ACCOUNT_VERIFICATION', 'ACCOUNT_VERIFICATION'), ('PASSWORD_RESET', 'PASSWORD_RESET')], default='ACCOUNT_VERIFICATION', max_length=100)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
