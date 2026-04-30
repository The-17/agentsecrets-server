from pathlib import Path
from decouple import config
from datetime import timedelta
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SECRET_KEY = config("SECRET_KEY")
ALLOWED_HOSTS = config("ALLOWED_HOSTS").split(" ")


DJANGO_APPS = [
    'jazzmin',
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


STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATIC_URL = "/static/"
MEDIA_URL = "/media/"
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static/"),
]
MEDIA_ROOT = os.path.join(BASE_DIR, "static/media")
STATICFILES_STORAGE = "whitenoise.storage.CompressedStaticFilesStorage"


STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    }
}

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

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

ENCRYPTION_KEY = config("ENCRYPTION_KEY")

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=6),
}

# ==========================================
# JAZZMIN ADMIN CONFIGURATION
# ==========================================

JAZZMIN_SETTINGS = {
    "site_title": "AgentSecrets Admin",
    "site_header": "AgentSecrets",
    "site_brand": "AgentSecrets",
    "welcome_sign": "Welcome to the AgentSecrets Secure Admin",
    "copyright": "The Seventeen",
    "search_model": ["accounts.User", "secrets_app.Project"],
    "user_avatar": "avatar",
    "topmenu_links": [
        {"name": "Home", "url": "admin:index", "permissions": ["auth.view_user"]},
        {"name": "Docs", "url": "https://agentsecrets.theseventeen.co/docs", "new_window": True},
    ],
    "show_sidebar": True,
    "navigation_expanded": False,
    "hide_apps": [],
    "hide_models": [],
    "icons": {
        "auth": "fas fa-users-cog",
        "auth.Group": "fas fa-users",
        "accounts.User": "fas fa-user-shield",
        "accounts.OneTimePassword": "fas fa-key",
        
        "secrets_app.Project": "fas fa-project-diagram",
        "secrets_app.Secret": "fas fa-user-secret",
        
        "workspaces.Workspace": "fas fa-building",
        "workspaces.Membership": "fas fa-id-badge",
        "workspaces.WorkspaceAllowlist": "fas fa-shield-alt",
        "workspaces.WorkspaceAllowlistLog": "fas fa-clipboard-list",
        "workspaces.AgentRegistration": "fas fa-robot",
        "workspaces.AgentToken": "fas fa-ticket-alt",
        "workspaces.AuditLogEntry": "fas fa-history",
        
        "telemetry.TelemetrySnapshot": "fas fa-satellite-dish",
        "telemetry.DailyMetricsAggregate": "fas fa-chart-line",
    },
    "default_icon_parents": "fas fa-chevron-circle-right",
    "default_icon_children": "fas fa-circle",
    "related_modal_active": True,
    "custom_css": None,
    "custom_js": None,
    "show_ui_builder": True,
}

JAZZMIN_UI_TWEAKS = {
    "theme": "simplex", # The absolute flattest, most minimal Bootswatch theme
    "dark_mode_theme": None,
    "navbar": "navbar-white navbar-light",
    "sidebar": "sidebar-light-primary",
    "no_navbar_border": True,
    "sidebar_nav_flat_style": True,
    "sidebar_nav_compact_style": True,
    "brand_colour": False,
    "navbar_small_text": False,
    "footer_small_text": True,
    "body_small_text": False,
    "brand_small_text": False,
    "sidebar_nav_small_text": False,
    "sidebar_disable_expand": False,
    "sidebar_nav_child_indent": False,
    "sidebar_nav_legacy_style": False,
    "layout_boxed": False,
    "footer_fixed": False,
    "sidebar_fixed": False,
    "navbar_fixed": False,
    "accent": "accent-primary",
}