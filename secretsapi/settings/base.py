from pathlib import Path
from decouple import config
from datetime import timedelta
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SECRET_KEY = config("SECRET_KEY")
ALLOWED_HOSTS = config("ALLOWED_HOSTS").split(" ")


DJANGO_APPS = [
    'unfold',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    "adrf",
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "ninja_extra",
    # "corsheaders",
    "rest_framework_simplejwt.token_blacklist",
]

LOCAL_APPS = [
    "apps.accounts",
    "apps.common",
    "apps.secrets_app",
    "apps.workspaces",
    "apps.telemetry",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

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

ROOT_URLCONF = 'secretsapi.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'secretsapi.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('POSTGRES_DB'),
        'USER': config('POSTGRES_USER'),
        'PASSWORD':config('POSTGRES_PASSWORD'),
        'HOST': config('POSTGRES_HOST'),
        'PORT':config('POSTGRES_PORT'),
        'OPTIONS': {
            'sslmode':'require'
        }
    }
}


REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle"
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/day",
        "user": "1000/day"
    }
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Secrets API",
    "DESCRIPTION": "Secrets API documentation",
    "VERSION": "1.0.0",
    "SECURITY": [
        {
            "bearerAuth": [],
        }
    ],
    "TAGS": [
        {"name": "Auth", "description": "Authentication endpoints"},
        {"name": "Projects", "description": "Projects management endpoints"},
        {"name": "Secrets", "description": "Secrets management endpoints"},
    ],
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

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

AUTH_USER_MODEL = 'accounts.user'


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static/"),
]
MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "static/media")

STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    }
}

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

ENCRYPTION_KEY = config("ENCRYPTION_KEY")
RESOLVER_SERVICE_KEY = config("RESOLVER_SERVICE_KEY", default="")

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=6),
}

# ==========================================
# UNFOLD ADMIN CONFIGURATION
# ==========================================

UNFOLD = {
    "SITE_TITLE": "AgentSecrets Admin",
    "SITE_HEADER": "AgentSecrets",
    "SITE_BRAND": "AgentSecrets",
    "SITE_SYMBOL": "shield-check",
    "SHOW_HISTORY": True,
    "SHOW_VIEW_ON_SITE": True,
    "COLORS": {
        "primary": {
            "50": "250 250 250",
            "100": "244 244 245",
            "200": "228 228 231",
            "300": "212 212 216",
            "400": "161 161 170",
            "500": "113 113 122",
            "600": "82 82 91",
            "700": "63 63 70",
            "800": "39 39 42",
            "900": "24 24 27",
            "950": "9 9 11",
        },
    },
}