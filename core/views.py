from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, get_user_model
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from .models import Conta
from .forms import ContaForm
from django.db.models import Sum, Q
from django.conf import settings
from django.http import HttpResponse
import os
from django.contrib.auth.decorators import login_required
from decouple import config
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

@login_required
def dashboard(request):
    """Tela principal com linha do tempo e estatísticas"""
    contas = Conta.objects.all().order_by('-criado_em')
    
    context = {
        'contas': contas,  
    }
    return render(request, 'dashboard.html', context)

@login_required
def cadastrar_conta(request):
    """Cadastrar nova conta"""
    if request.method == 'POST':
        form = ContaForm(request.POST)
        if form.is_valid():
            conta = form.save()
            messages.success(request, f'Conta "{conta.titulo}" cadastrada com sucesso!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Erro ao cadastrar conta. Verifique os dados informados.')
    else:
        form = ContaForm()
    
    return render(request, 'cadastrar.html', {'form': form})

@login_required
def editar_conta(request, pk):
    """Editar conta existente"""
    conta = get_object_or_404(Conta, pk=pk)
    
    if request.method == 'POST':
        form = ContaForm(request.POST, instance=conta)
        if form.is_valid():
            conta = form.save()
            messages.success(request, f'Conta "{conta.titulo}" atualizada com sucesso!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Erro ao atualizar conta. Verifique os dados informados.')
    else:
        form = ContaForm(instance=conta)
    
    return render(request, 'editar.html', {'form': form, 'conta': conta})

@login_required
def excluir_conta(request, pk):
    """Excluir conta"""
    conta = get_object_or_404(Conta, pk=pk)
    
    if request.method == 'POST':
        titulo_conta = conta.titulo
        conta.delete()
        messages.success(request, f'Conta "{titulo_conta}" excluída com sucesso!')
        return redirect('dashboard')
    
    return render(request, 'excluir.html', {'conta': conta})

@login_required
def api_contas_json(request):
    """API JSON para dados das contas (para gráficos)"""
    contas = Conta.objects.all().values('titulo', 'descricao', 'data', 'criado_em')
    contas_list = []
    
    for conta in contas:
        contas_list.append({
            'titulo': conta['titulo'],
            'descricao': conta['descricao'],
            'data': conta['data'].isoformat(),
            'criado_em': conta['criado_em'].isoformat(),
        })
    
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
