from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.db.models import Q, Sum
from django.conf import settings
from django.http import HttpResponse
from decouple import config

from .models import Conta, Base
from .forms import ContaForm


# ----------------- helpers -----------------
def _bases_do_usuario(user):
    """Retorna as bases vinculadas ao usuário (ou vazio)."""
    try:
        return user.bases.all()
    except Exception:
        return Base.objects.none()

def _resolver_base_para_request(request):
    """
    Define a base-alvo da requisição:
      1) (superuser) se vier ?base=<id> ou POST['base']
      2) request.current_base (se middleware estiver habilitado)
      3) primeira base do usuário
    """
    if request.user.is_authenticated and request.user.is_superuser:
        base_id = request.POST.get('base') or request.GET.get('base')
        if base_id:
            try:
                return Base.objects.get(pk=base_id)
            except Base.DoesNotExist:
                pass

    current_base = getattr(request, 'current_base', None)
    if current_base:
        return current_base

    if request.user.is_authenticated:
        return _bases_do_usuario(request.user).first()

    return None


# ----------------- auth -----------------
def login_view(request):
    if request.method == 'POST':
        identificador = (request.POST.get('username') or '').strip()
        senha = request.POST.get('password') or ''
        User = get_user_model()

        user = None
        try:
            validate_email(identificador)
            qs = User.objects.filter(email__iexact=identificador)
            if qs.count() > 1:
                messages.error(request, 'Há mais de um usuário com este e-mail. Contate o administrador.')
                return render(request, 'login.html', {'last_username': identificador})
            user = qs.first()
        except ValidationError:
            pass

        if user is None:
            user = User.objects.filter(username__iexact=identificador).first()

        if user:
            user_auth = authenticate(request, username=user.username, password=senha)
            if user_auth is not None:
                login(request, user_auth)
                return redirect('dashboard')
            else:
                messages.error(request, 'Senha incorreta.')
        else:
            messages.error(request, 'Usuário não encontrado.')

    return render(request, 'login.html')


# ----------------- app -----------------
@login_required
def dashboard(request):
    """Tela principal com linha do tempo e estatísticas (escopado por base)."""
    base_atual = _resolver_base_para_request(request)

    if request.user.is_superuser:
        contas = Conta.objects.filter(base=base_atual).order_by('-data') if base_atual else Conta.objects.all().order_by('-data')
        bases = Base.objects.all()
    else:
        if base_atual:
            contas = Conta.objects.filter(base=base_atual).order_by('-data')
        else:
            contas = Conta.objects.filter(base__in=_bases_do_usuario(request.user)).order_by('-data')
        bases = _bases_do_usuario(request.user)

    context = {
        'contas': contas,
        'base_atual': base_atual,
        'bases': bases,  # para o seletor no template
    }
    return render(request, 'dashboard.html', context)


@login_required
def cadastrar_conta(request):
    """Cadastrar nova conta — garante que `conta.base` seja definida antes do save()."""
    if request.method == 'POST':
        form = ContaForm(request.POST)
        if form.is_valid():
            conta = form.save(commit=False)
            conta.base = _resolver_base_para_request(request)

            if not conta.base:
                form.add_error(None, 'Você não está vinculado a nenhuma base. Peça para um administrador configurar seu acesso.')
            else:
                conta.save()
                messages.success(request, f'Conta "{conta.titulo}" cadastrada com sucesso!')
                return redirect('dashboard')
        else:
            messages.error(request, 'Erro ao cadastrar conta. Verifique os dados informados.')
    else:
        form = ContaForm()

    # opcional: passar bases para superuser escolher num <select>
    bases = Base.objects.all() if request.user.is_superuser else None
    return render(request, 'cadastrar.html', {'form': form, 'bases': bases})


@login_required
def editar_conta(request, pk):
    """Editar conta existente — só se pertencer à base do usuário (ou superuser)."""
    if request.user.is_superuser:
        conta = get_object_or_404(Conta, pk=pk)
    else:
        conta = get_object_or_404(Conta, pk=pk, base__in=_bases_do_usuario(request.user))

    if request.method == 'POST':
        form = ContaForm(request.POST, instance=conta)
        if form.is_valid():
            obj = form.save(commit=False)
            # não permita trocar a base aqui via form comum
            obj.base = conta.base
            obj.save()
            messages.success(request, f'Conta "{obj.titulo}" atualizada com sucesso!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Erro ao atualizar conta. Verifique os dados informados.')
    else:
        form = ContaForm(instance=conta)

    bases = Base.objects.all() if request.user.is_superuser else None
    return render(request, 'editar.html', {'form': form, 'conta': conta, 'bases': bases})


@login_required
def excluir_conta(request, pk):
    """Excluir conta — só se pertencer à base do usuário (ou superuser)."""
    if request.user.is_superuser:
        conta = get_object_or_404(Conta, pk=pk)
    else:
        conta = get_object_or_404(Conta, pk=pk, base__in=_bases_do_usuario(request.user))

    if request.method == 'POST':
        titulo_conta = conta.titulo
        conta.delete()
        messages.success(request, f'Conta "{titulo_conta}" excluída com sucesso!')
        return redirect('dashboard')

    return render(request, 'excluir.html', {'conta': conta})


@login_required
def api_contas_json(request):
    """API JSON escopada por base do usuário."""
    base_atual = _resolver_base_para_request(request)

    if request.user.is_superuser:
        qs = Conta.objects.filter(base=base_atual) if base_atual else Conta.objects.all()
    else:
        qs = Conta.objects.filter(base=base_atual) if base_atual else Conta.objects.filter(base__in=_bases_do_usuario(request.user))

    contas = qs.values('titulo', 'descricao', 'data', 'criado_em')

    contas_list = [{
        'titulo': c['titulo'],
        'descricao': c['descricao'],
        'data': c['data'].isoformat() if c['data'] else None,
        'criado_em': c['criado_em'].isoformat() if c['criado_em'] else None,
    } for c in contas]

    return JsonResponse({'contas': contas_list})


@login_required
def powerbi(request):
    url = ("https://app.powerbi.com/view?"
           "r=eyJrIjoiM2JlODRjN2QtYTUwMC00NjIwLTk3MjEtOGFlMmRlMTBmNTExIiwidCI6ImJmODhhNDU2LTQwZTctNDg5OC1hYmMwLWUwNmM0MWVmZTliOCJ9")
    ctx = {
        "powerbi_url": url,
        "back_url": "/",
    }
    return render(request, "powerbi.html", ctx)
