# core/middleware.py
from django.shortcuts import redirect
from django.urls import reverse, NoReverseMatch
from .models import UserSecurity

class ForcePasswordChangeMiddleware:
    """
    Se o usuário estiver autenticado e marcado com must_change_password=True,
    só deixa acessar a view de troca (e login/logout/static/admin).
    Coloque após AuthenticationMiddleware.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def _is_exempt_path(self, request):
        path = request.path
        if path.startswith("/static/") or path.startswith("/admin/"):
            return True

        allowed_names = ("force_password_change", "login", "logout", "password_reset", "password_reset_done")
        for name in allowed_names:
            try:
                if path == reverse(name):
                    return True
            except NoReverseMatch:
                pass
        return False

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user and user.is_authenticated and not self._is_exempt_path(request):
            sec, _ = UserSecurity.objects.get_or_create(user=user)
            if sec.must_change_password:
                return redirect("force_password_change")
        return self.get_response(request)