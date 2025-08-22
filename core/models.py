from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import models

class UserCreateWithEmailForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_email(self):
        email = self.cleaned_data["email"].strip()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Este e-mail já está em uso.")
        return email

class UserChangeWithEmailForm(UserChangeForm):
    email = forms.EmailField(required=True)

    class Meta(UserChangeForm.Meta):
        model = User
        fields = ("username", "email", "first_name", "last_name", "is_active", "is_staff", "is_superuser")


class Conta(models.Model):
    titulo = models.CharField(max_length=200, verbose_name='Título')
    descricao = models.TextField(verbose_name='Descrição')
    data = models.DateField(verbose_name='Data')
    criado_em = models.DateTimeField(auto_now_add=True, verbose_name='Criado em')
    
    class Meta:
        ordering = ['-data', '-criado_em']
        verbose_name = 'Conta'
        verbose_name_plural = 'Contas'
    
    def __str__(self):
        return self.titulo