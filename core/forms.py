from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from .models import Conta

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

class ContaForm(forms.ModelForm):
    class Meta:
        model = Conta
        fields = ['titulo', 'descricao', 'data']
        widgets = {
            'titulo': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Digite o título'
            }),
            'descricao': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Digite a descrição',
                'rows': 4
            }),
            'data': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            })
        }

        