# core/storages.py
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

try:
    from storages.backends.s3boto3 import S3Boto3Storage
except Exception as e:  # django-storages/boto3 não instalado
    S3Boto3Storage = None


class S3PrivateMediaStorage(S3Boto3Storage):
    """
    Storage privado em S3, pronto para CloudFront.
    - Lê configs do settings via getattr (evita AttributeError no import).
    - Só valida obrigatórios no __init__, quando o storage é realmente usado.
    """
    def __init__(self, *args, **kwargs):
        if S3Boto3Storage is None:
            raise ImproperlyConfigured(
                "Instale as dependências: pip install 'django-storages[boto3]'"
            )

        bucket_name   = getattr(settings, "AWS_STORAGE_BUCKET_NAME", None)
        region_name   = getattr(settings, "AWS_S3_REGION_NAME", None)
        custom_domain = getattr(settings, "AWS_S3_CUSTOM_DOMAIN", None)  
        location      = (getattr(settings, "AWS_S3_LOCATION", "") or "").strip("/")  

        if not bucket_name:
            raise ImproperlyConfigured("Defina AWS_STORAGE_BUCKET_NAME no settings ou ambiente.")

        kwargs.setdefault("bucket_name", bucket_name)
        kwargs.setdefault("custom_domain", custom_domain)   
        kwargs.setdefault("region_name", region_name)
        kwargs.setdefault("default_acl", "private")
        kwargs.setdefault("file_overwrite", False)
        kwargs.setdefault("location", location)             

        if custom_domain:
            kwargs.setdefault("querystring_auth", False)

        super().__init__(*args, **kwargs)
