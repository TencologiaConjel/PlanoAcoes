from django.conf import settings
from django.db import models
from django.db.models import UniqueConstraint
from django.utils.text import slugify
from django.utils import timezone
from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver

import os, mimetypes, uuid, re


# ========= Base / Membership =========

class Base(models.Model):
    nome = models.CharField(max_length=150, unique=True)
    slug = models.SlugField(unique=True)
    ativo = models.BooleanField(default=True)
    criado_em = models.DateTimeField(auto_now_add=True)

    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL, through='Membership', related_name='bases', blank=True
    )

    class Meta:
        ordering = ['nome']
        verbose_name = 'Base'
        verbose_name_plural = 'Bases'

    def __str__(self):
        return self.nome

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.nome)
        super().save(*args, **kwargs)


class Membership(models.Model):
    ROLE_CHOICES = [
        ('owner', 'Proprietário'),
        ('admin', 'Admin'),
        ('viewer', 'Visualizador'),
    ]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='memberships')
    base = models.ForeignKey(Base, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            UniqueConstraint(fields=['user', 'base'], name='uniq_user_base'),
        ]
        verbose_name = 'Vínculo'
        verbose_name_plural = 'Vínculos'

    def __str__(self):
        return f'{self.user} @ {self.base} ({self.role})'


# ========= Conta =========

class ContaQuerySet(models.QuerySet):
    def for_user(self, user):
        if getattr(user, 'is_superuser', False):
            return self
        return self.filter(base__in=user.bases.all())


class Conta(models.Model):
    # deixe null=True/blank=True enquanto faz o backfill; depois troque pra False numa migração final
    base = models.ForeignKey(Base, on_delete=models.CASCADE, related_name='contas',
                             null=True, blank=True)

    titulo = models.CharField(max_length=200, verbose_name='Título')
    descricao = models.TextField(verbose_name='Descrição')
    data = models.DateField(verbose_name='Data')
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name='Criado em')

    objects = ContaQuerySet.as_manager()

    class Meta:
        ordering = ['-data', '-criado_em']
        verbose_name = 'Conta'
        verbose_name_plural = 'Contas'
        indexes = [
            models.Index(fields=['base', 'data']),
            models.Index(fields=['base', 'criado_em']),
        ]

    def __str__(self):
        return self.titulo


# ========= Anexo (S3 via django-storages) =========

from .storages import S3PrivateMediaStorage  # <- seu storage do app

_filename_sanitize_re = re.compile(r"[^\w\-. ]+", re.UNICODE)
def _safe_name(name: str) -> str:
    base = os.path.basename(name or "")
    base = _filename_sanitize_re.sub("_", base).strip() or "arquivo"
    return base

def anexo_upload_to(instance, filename: str):
    """
    Caminho organizado e único: anexos/<base>/conta_<id>/<YYYY/MM>/<uuid>_<nome>
    Usa conta.base sempre que possível (inline formset preenche instance.conta).
    """
    base = getattr(instance, "base", None)
    if not base and getattr(instance, "conta", None):
        base = instance.conta.base
    base_slug = getattr(base, "slug", "sem-base")
    conta_id = getattr(instance, "conta_id", None) or "sem"
    return f"anexos/{base_slug}/conta_{conta_id}/{timezone.now():%Y/%m}/{uuid.uuid4().hex}_{_safe_name(filename)}"


class AnexoQuerySet(models.QuerySet):
    def for_user(self, user):
        if getattr(user, "is_superuser", False):
            return self
        return self.filter(base__in=user.bases.all())


class Anexo(models.Model):
    base   = models.ForeignKey("Base", on_delete=models.CASCADE, related_name="anexos")
    conta  = models.ForeignKey("Conta", on_delete=models.CASCADE, related_name="anexos")
    arquivo = models.FileField(
        storage=S3PrivateMediaStorage(),
        upload_to=anexo_upload_to,
        max_length=512,
    )
    nome_original = models.CharField(max_length=255, blank=True)
    content_type  = models.CharField(max_length=120, blank=True)
    tamanho       = models.BigIntegerField(null=True, blank=True)
    uploaded_by   = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    criado_em     = models.DateTimeField(auto_now_add=True)

    objects = AnexoQuerySet.as_manager()

    class Meta:
        ordering = ["-criado_em"]
        indexes = [
            models.Index(fields=["base", "conta"]),
            models.Index(fields=["criado_em"]),
        ]

    def __str__(self):
        return self.nome_original or os.path.basename(self.arquivo.name)

    @property
    def filename(self):
        return os.path.basename(self.arquivo.name)

    def save(self, *args, **kwargs):
        if self.arquivo and not self.nome_original:
            self.nome_original = os.path.basename(getattr(self.arquivo, "name", "")) or self.nome_original
        if self.arquivo and not self.tamanho:
            try:
                self.tamanho = self.arquivo.size
            except Exception:
                pass
        if not self.content_type and self.nome_original:
            self.content_type = mimetypes.guess_type(self.nome_original)[0] or ""
        if self.conta_id and not self.base_id:
            self.base = self.conta.base
        super().save(*args, **kwargs)



@receiver(post_delete, sender=Anexo)
def _delete_file_on_instance_delete(sender, instance: Anexo, **kwargs):
    try:
        if instance.arquivo and instance.arquivo.name:
            storage = instance.arquivo.storage
            if storage.exists(instance.arquivo.name):
                storage.delete(instance.arquivo.name)
    except Exception:
        pass


@receiver(pre_save, sender=Anexo)
def _delete_old_file_on_change(sender, instance: Anexo, **kwargs):
    """
    Se trocar o arquivo de um anexo existente, apaga o arquivo antigo no storage.
    """
    if not instance.pk:
        return
    try:
        old = Anexo.objects.get(pk=instance.pk)
    except Anexo.DoesNotExist:
        return
    old_file = getattr(old, "arquivo", None)
    new_file = getattr(instance, "arquivo", None)
    if old_file and old_file.name and old_file != new_file:
        try:
            storage = old_file.storage
            if storage.exists(old_file.name):
                storage.delete(old_file.name)
        except Exception:
            pass
