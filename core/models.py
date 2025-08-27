# models.py
from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Base(models.Model):
    nome = models.CharField(max_length=150, unique=True)
    slug = models.SlugField(unique=True)
    ativo = models.BooleanField(default=True)
    criado_em = models.DateTimeField(auto_now_add=True)

    # Usuários vinculados a esta base (via tabela de junção Membership)
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
        unique_together = ('user', 'base')
        verbose_name = 'Vínculo'
        verbose_name_plural = 'Vínculos'

    def __str__(self):
        return f'{self.user} @ {self.base} ({self.role})'


class ContaQuerySet(models.QuerySet):
    def for_user(self, user):
        """Filtra contas que o usuário pode ver (todas se superuser)."""
        if getattr(user, 'is_superuser', False):
            return self
        return self.filter(base__in=user.bases.all())


class Conta(models.Model):
    # Passo 1 da migração: deixe null/blank True. Depois de popular, torne obrigatório.
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
