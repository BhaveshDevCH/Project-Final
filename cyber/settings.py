"""
Django settings for cyber project.

Generated by 'django-admin startproject' using Django 3.1.7.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.1/ref/settings/
"""
import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'l61o_e7uq*m@zs^t)$0g3-9ux8q(m(s*f1r7hg+4@l8gn_^ii4'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'Dashboard',
    'rest_framework',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    'whitenoise.middleware.WhiteNoiseMiddleware',
]

ROOT_URLCONF = 'cyber.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
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

WSGI_APPLICATION = 'cyber.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.1/ref/settings/#databases

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.mysql',
#         'NAME': 'cyber12',
#         'USER':'Cyber12345',
#         'PASSWORD':'ShCh@#',
#         'HOST':'184.168.112.45',
#         'PORT':'3306',

#     }
# }

DATABASES = {
'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'Garud', 
        'USER': 'postgres', 
        'PASSWORD': 'Bhavesh@123',
        'HOST': '127.0.0.1', 
        'PORT': '5432',
    }
}


# DATABASES = {
# 'default': {
#         'ENGINE': 'django.db.backends.postgresql_psycopg2',
#         'NAME': 'garud_db',
#         'USER':'garud',
#         'PASSWORD':'ShCh@#',
#         'HOST': '35.223.69.150',
#         # 'HOST': '127.0.0.1',
#         # 'PORT':'3306'
#     }
# }



# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators

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


# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.1/howto/static-files/

STATICFILES_STORAGE = 'whitenoise.storage.CompressedStaticFilesStorage'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

MEDIA_ROOT = os.path.join(BASE_DIR, 'static/images')

MEDIA_URL = '/images/'


# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'chinmay.cyberhawkz@gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_PASSWORD = 'kxvbqzzfuldtxplz'


# Logger
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
       'message': {
             'format': '%(message)s'
         }
    },
    'handlers': {
        'login_logout_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'temp/loginLogoutLogs.txt',
        },
        'search_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'temp/SearchLogs.txt',
        }, 
        'api_logs_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'temp/apiLogs.txt',
        }, 
    },
    'loggers': {
        'search': {
            'handlers': ['search_file'],
            'level': 'INFO',
        },
        'auth': {
            'handlers': ['login_logout_file'],
            'level': 'INFO',
        },
        'api_logs': {
            'handlers': ['api_logs_file'],
            'level': 'INFO',
        },
    }
}


REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}


FILE_SAMPLES = os.path.join(BASE_DIR , 'fileSamples')
UPLOAD_FILE_TYPES = ['application/pdf']