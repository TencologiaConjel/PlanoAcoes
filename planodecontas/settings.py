from pathlib import Path
import dj_database_url
from decouple import config
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')

DEBUG = True

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'core',
    'storages',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'planodecontas.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'planodecontas.wsgi.application'

if os.environ.get('DATABASE_URL'):
    DATABASES = {
        'default': dj_database_url.config(
            default=os.environ.get('DATABASE_URL'),
            conn_max_age=600,
            ssl_require=True
        )
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'pt-br'

TIME_ZONE = 'America/Sao_Paulo'

USE_I18N = True

USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfile')
MEDIA_URL = 'media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL = 'login'

LOGOUT_REDIRECT_URL = 'login'

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

CSRF_TRUSTED_ORIGINS = [
    'https://planoacoes-production.up.railway.app'
]


from decouple import config

AWS_ACCESS_KEY_ID        = config("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY    = config("AWS_SECRET_ACCESS_KEY")
AWS_STORAGE_BUCKET_NAME  = config("AWS_STORAGE_BUCKET_NAME", default="webserviceconjel")
AWS_S3_REGION_NAME       = config("AWS_S3_REGION_NAME",  default="us-east-2")

# Informe APENAS o host do CloudFront (sem https)
AWS_CLOUDFRONT_DOMAIN    = config("AWS_CLOUDFRONT_DOMAIN", default="dXXXX.cloudfront.net")
AWS_S3_CUSTOM_DOMAIN     = AWS_CLOUDFRONT_DOMAIN.replace("https://", "").replace("http://", "")

AWS_DEFAULT_ACL = None
AWS_S3_OBJECT_PARAMETERS = {"CacheControl": "max-age=86400"}

# Se sua distro for PÚBLICA para o viewer (Restrict Viewer Access = No):
AWS_QUERYSTRING_AUTH = False

# Storage padrão em S3
DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"

MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/"


def _clean_domain(d):
    if not d:
        return None
    d = str(d)
    d = d.replace("\u200b", "").replace("\ufeff", "")
    d = d.strip(" \t\r\n'\"").lstrip("= ")
    d = d.replace("https://", "").replace("http://", "").strip("/")
    return d.split("/")[0] if d else None

RAW_CF = os.getenv("AWS_CLOUDFRONT_DOMAIN") or ""
AWS_CLOUDFRONT_DOMAIN = _clean_domain(RAW_CF)

import logging
logging.getLogger(__name__).warning(
    "CF domain raw=%r sanitized=%r",
    RAW_CF, AWS_CLOUDFRONT_DOMAIN
)
