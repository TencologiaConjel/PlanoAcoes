
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .forms import UserCreateWithEmailForm, UserChangeWithEmailForm
from .models import Conta

class UserAdmin(BaseUserAdmin):
    add_form = UserCreateWithEmailForm
    form = UserChangeWithEmailForm

    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("username", "email", "password1", "password2")}),
    )
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Informações pessoais", {"fields": ("first_name", "last_name", "email")}),
        ("Permissões", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Datas importantes", {"fields": ("last_login", "date_joined")}),
    )

admin.site.unregister(User)
admin.site.register(User, UserAdmin)

@admin.register(Conta)
class ContaAdmin(admin.ModelAdmin):
    list_display = ['titulo', 'descricao', 'data', 'criado_em']
    list_filter = ['data', 'criado_em']
    ordering = ['-data', '-criado_em']
    date_hierarchy = 'data'
    search_fields = ['titulo', 'descricao']
    readonly_fields = ['criado_em']
    
    fieldsets = (
        (None, {
            'fields': ('titulo', 'descricao', 'data')
        }),
        ('Informações do Sistema', {
            'fields': ('criado_em',),
            'classes': ('collapse',),
        }),
    )