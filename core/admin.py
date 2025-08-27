from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model

from .forms import UserCreateWithEmailForm, UserChangeWithEmailForm
from .models import Base, Membership, Conta

User = get_user_model()


# ===========================
# Inlines
# ===========================
class MembershipInline(admin.TabularInline):
    model = Membership
    fk_name = "user"
    extra = 0
    autocomplete_fields = ["base"]


# ===========================
# User
# ===========================
# Desregistra o User padrão (se já estiver registrado)
try:
    admin.site.unregister(User)
except admin.sites.NotRegistered:
    pass


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    add_form = UserCreateWithEmailForm
    form = UserChangeWithEmailForm
    inlines = [MembershipInline]

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("username", "email", "password1", "password2"),
        }),
    )
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Informações pessoais", {"fields": ("first_name", "last_name", "email")}),
        ("Permissões", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Datas importantes", {"fields": ("last_login", "date_joined")}),
    )

    list_display = ("username", "email", "is_staff", "is_superuser")
    search_fields = ("username", "email")


# ===========================
# Base
# ===========================
@admin.register(Base)
class BaseAdmin(admin.ModelAdmin):
    list_display = ("nome", "slug", "ativo", "criado_em")
    list_filter = ("ativo",)
    search_fields = ("nome", "slug")
    prepopulated_fields = {"slug": ("nome",)}


# ===========================
# Membership
# ===========================
@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "base", "role", "joined_at")
    list_filter = ("role", "base")
    search_fields = ("user__username", "user__email", "base__nome")
    autocomplete_fields = ["user", "base"]


# ===========================
# Conta
# ===========================
@admin.register(Conta)
class ContaAdmin(admin.ModelAdmin):
    list_display = ["titulo", "base", "data", "criado_em"]
    list_filter = ["base", "data", "criado_em"]
    ordering = ["-data", "-criado_em"]
    date_hierarchy = "data"
    search_fields = ["titulo", "descricao"]
    readonly_fields = ["criado_em"]
    list_select_related = ("base",)
    autocomplete_fields = ["base"]

    fieldsets = (
        (None, {"fields": ("base", "titulo", "descricao", "data")}),
        ("Informações do Sistema", {
            "fields": ("criado_em",),
            "classes": ("collapse",),
        }),
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(base__in=request.user.bases.all())

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "base" and not request.user.is_superuser:
            kwargs["queryset"] = request.user.bases.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def save_model(self, request, obj, form, change):
        if not getattr(obj, "base_id", None) and not request.user.is_superuser:
            obj.base = request.user.bases.first()
        super().save_model(request, obj, form, change)
