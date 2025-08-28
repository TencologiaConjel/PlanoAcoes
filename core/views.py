from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.http import JsonResponse, HttpResponseForbidden
from django.db.models import Q, Sum, Prefetch
from django.conf import settings

from .models import Conta, Base, Anexo
from .forms import ContaForm

import os, base64, logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

AWS_BUCKET       = getattr(settings, "AWS_STORAGE_BUCKET_NAME", None)
AWS_REGION       = getattr(settings, "AWS_S3_REGION_NAME", "sa-east-1")
AWS_S3_LOCATION  = (getattr(settings, "AWS_S3_LOCATION", "") or os.getenv("AWS_S3_LOCATION", "") or "").strip("/")

CF_DOMAIN        = getattr(settings, "AWS_CLOUDFRONT_DOMAIN", None) or os.getenv("AWS_CLOUDFRONT_DOMAIN")
CF_KEY_ID        = getattr(settings, "CLOUDFRONT_KEY_ID", None) or os.getenv("CLOUDFRONT_KEY_ID")
CF_PRIV_B64      = getattr(settings, "CLOUDFRONT_PRIVATE_KEY_B64", None) or os.getenv("CLOUDFRONT_PRIVATE_KEY_B64")
CF_PRIV_PEM      = getattr(settings, "CLOUDFRONT_PRIVATE_KEY", None) or os.getenv("CLOUDFRONT_PRIVATE_KEY")

S3_ANEXOS_ROOT   = getattr(settings, "S3_ANEXOS_ROOT", "anexos_v2")

try:
    from botocore.signers import CloudFrontSigner
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception:
    CloudFrontSigner = None

def _s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=getattr(settings, "AWS_ACCESS_KEY_ID", None),
        aws_secret_access_key=getattr(settings, "AWS_SECRET_ACCESS_KEY", None),
        region_name=AWS_REGION,
    )

_CF_SIGNER = None
def _get_cf_signer():
    """Retorna CloudFrontSigner se houver DOMAIN + KEY_ID + PRIVATE_KEY."""
    global _CF_SIGNER
    if _CF_SIGNER is not None:
        return _CF_SIGNER
    if not (CF_DOMAIN and CF_KEY_ID and (CF_PRIV_PEM or CF_PRIV_B64) and CloudFrontSigner):
        _CF_SIGNER = None
        return None

    pem = CF_PRIV_PEM
    if not pem and CF_PRIV_B64:
        pem = base64.b64decode(CF_PRIV_B64).decode("utf-8")

    def rsa_signer(message: bytes):
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        return key.sign(message, padding.PKCS1v15(), hashes.SHA1())

    _CF_SIGNER = CloudFrontSigner(CF_KEY_ID, rsa_signer)
    return _CF_SIGNER

def _rel_to_abs_key(rel_key: str) -> str:
    """Converte a chave RELATIVA (FileField.name) em chave ABSOLUTA do S3, aplicando Origin Path se existir."""
    return f"{AWS_S3_LOCATION}/{rel_key}" if AWS_S3_LOCATION else rel_key

def cloudfront_signed_url(rel_key: str, expires_in: int = 600) -> str | None:
    """
    Gera URL (assinada) via CloudFront para a chave RELATIVA (NÃO incluir Origin Path aqui).
    Retorna None se CF não estiver configurado.
    """
    if not CF_DOMAIN:
        return None
    from datetime import datetime, timedelta, timezone as tz
    url = f"https://{CF_DOMAIN}/{rel_key}"
    signer = _get_cf_signer()
    if not signer:
        return url  # distribuição pública (sem assinatura)
    exp = datetime.now(tz=tz.utc) + timedelta(seconds=expires_in)
    return signer.generate_presigned_url(url, date_less_than=exp)

def s3_presigned_url(abs_key: str, expires_in: int = 600) -> str:
    """Fallback: URL pré-assinada do S3 direto (ABS key = com Origin Path, se houver)."""
    return _s3_client().generate_presigned_url(
        "get_object",
        Params={"Bucket": AWS_BUCKET, "Key": abs_key},
        ExpiresIn=expires_in,
    )

# =========================
# Helpers de base/escopo
# =========================
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

def _contas_queryset_para_dashboard(request):
    """
    QuerySet de Contas para o dashboard:
    - Escopo por base/usuário
    - select_related('base') + prefetch dos anexos com only() para campos usados no template
    - Ordenação por data e criado_em (desc)
    """
    anexos_qs = Anexo.objects.only(
        'id', 'arquivo', 'nome_original', 'content_type', 'tamanho', 'criado_em', 'conta_id', 'base_id'
    )

    if request.user.is_superuser:
        base_atual = _resolver_base_para_request(request)
        qs = Conta.objects.select_related('base')
        if base_atual:
            qs = qs.filter(base=base_atual)
    else:
        bases_user = _bases_do_usuario(request.user)
        qs = Conta.objects.select_related('base').filter(base__in=bases_user)

    qs = qs.prefetch_related(Prefetch('anexos', queryset=anexos_qs)).order_by('-data', '-criado_em')
    return qs

# =========================
# Auth
# =========================
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

# =========================
# App
# =========================
@login_required
def dashboard(request):
    """Tela principal com linha do tempo e estatísticas (escopado por base)."""
    base_atual = _resolver_base_para_request(request)

    # Queryset otimizado com anexos prefetch
    contas = _contas_queryset_para_dashboard(request)

    # Bases para o seletor
    bases = Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user)

    context = {
        'contas': contas,
        'base_atual': base_atual,  # caso algum template use
        'bases': bases,
    }
    return render(request, 'dashboard.html', context)

@login_required
def cadastrar_conta(request):
    """
    Cadastrar nova conta — garante que `conta.base` seja definida e faz upload dos anexos (múltiplos).
    """
    if request.method == 'POST':
        form = ContaForm(request.POST)
        files = request.FILES.getlist('anexos')  # <input name="anexos" multiple>
        if form.is_valid():
            conta = form.save(commit=False)
            conta.base = _resolver_base_para_request(request)

            if not conta.base:
                form.add_error(None, 'Você não está vinculado a nenhuma base. Peça para um administrador configurar seu acesso.')
            else:
                conta.save()
                # Upload dos anexos
                for f in files:
                    if not f:
                        continue
                    Anexo.objects.create(
                        base=conta.base,
                        conta=conta,
                        arquivo=f,                  # sobe via storage configurado
                        nome_original=getattr(f, 'name', ''),
                        uploaded_by=request.user,
                    )
                messages.success(request, f'Conta "{conta.titulo}" cadastrada com sucesso!')
                return redirect('dashboard')
        else:
            messages.error(request, 'Erro ao cadastrar conta. Verifique os dados informados.')
    else:
        form = ContaForm()

    bases = Base.objects.all() if request.user.is_superuser else None
    return render(request, 'cadastrar.html', {'form': form, 'bases': bases})

@login_required
def editar_conta(request, pk):
    """Editar conta existente — só se pertencer à base do usuário (ou superuser)."""
    if request.user.is_superuser:
        conta = get_object_or_404(Conta.objects.select_related('base'), pk=pk)
    else:
        conta = get_object_or_404(
            Conta.objects.select_related('base'),
            pk=pk,
            base__in=_bases_do_usuario(request.user)
        )

    if request.method == 'POST':
        form = ContaForm(request.POST, instance=conta)
        files = request.FILES.getlist('anexos')  # múltiplos
        if form.is_valid():
            obj = form.save(commit=False)
            obj.base = conta.base  # não permitir troca de base aqui
            obj.save()

            for f in files:
                if not f:
                    continue
                Anexo.objects.create(
                    base=obj.base,
                    conta=obj,
                    arquivo=f,
                    nome_original=getattr(f, 'name', ''),
                    uploaded_by=request.user,
                )

            messages.success(request, f'Conta "{obj.titulo}" atualizada com sucesso!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Erro ao atualizar conta. Verifique os dados informados.')
    else:
        form = ContaForm(instance=conta)

    bases = Base.objects.all() if request.user.is_superuser else None
    anexos = conta.anexos.all()
    return render(request, 'editar.html', {'form': form, 'conta': conta, 'bases': bases, 'anexos': anexos})

@login_required
def excluir_conta(request, pk):
    """Excluir conta — só se pertencer à base do usuário (ou superuser)."""
    if request.user.is_superuser:
        conta = get_object_or_404(Conta, pk=pk)
    else:
        conta = get_object_or_404(Conta, pk=pk, base__in=_bases_do_usuario(request.user))

    if request.method == 'POST':
        titulo_conta = conta.titulo

        # remove fisicamente os anexos (S3) antes de excluir a conta
        for ax in list(conta.anexos.all()):
            try:
                ax.arquivo.delete(save=False)  # deleta arquivo do storage
            except Exception as e:
                logger.warning("Falha ao deletar arquivo do S3 (%s): %s", getattr(ax, "id", "?"), e)
            ax.delete()

        conta.delete()
        messages.success(request, f'Conta "{titulo_conta}" excluída com sucesso!')
        return redirect('dashboard')

    return render(request, 'excluir.html', {'conta': conta})

@login_required
def baixar_anexo(request, pk):
    """
    Redireciona para URL assinada na CloudFront (ou S3), após validar o escopo da base.
    - Usa a CHAVE RELATIVA que está no FileField (ex.: 'anexos_v2/...').
    - Se sua distribuição tem Origin Path, NÃO colocar na URL; apenas na chave do S3.
    """
    anexo = get_object_or_404(Anexo.objects.select_related('base', 'conta'), pk=pk)
    if not (request.user.is_superuser or request.user.bases.filter(pk=anexo.base_id).exists()):
        return HttpResponseForbidden('Sem permissão para este anexo.')

    rel_key = anexo.arquivo.name  # chave relativa no storage
    if not rel_key:
        messages.error(request, "Arquivo não encontrado para este anexo.")
        return redirect('editar_conta', pk=anexo.conta_id)

    abs_key = _rel_to_abs_key(rel_key)

    try:
        url = cloudfront_signed_url(rel_key, 600) or s3_presigned_url(abs_key, 600)
        return redirect(url)
    except Exception as e:
        logger.exception("Erro ao gerar URL do anexo %s: %s", pk, e)
        messages.error(request, "Não foi possível gerar a URL do anexo.")
        return redirect('editar_conta', pk=anexo.conta_id)

@login_required
def excluir_anexo(request, pk):
    """
    Exclui o anexo (arquivo + registro), se o usuário tiver acesso à base.
    """
    anexo = get_object_or_404(Anexo.objects.select_related('base', 'conta'), pk=pk)
    if not (request.user.is_superuser or request.user.bases.filter(pk=anexo.base_id).exists()):
        return HttpResponseForbidden('Sem permissão para este anexo.')

    conta_id = anexo.conta_id
    if request.method == 'POST':
        try:
            anexo.arquivo.delete(save=False)  # remove do S3
        except Exception as e:
            logger.warning("Falha ao deletar arquivo do S3 (anexo %s): %s", pk, e)
        anexo.delete()
        messages.success(request, 'Anexo excluído.')
    return redirect('editar_conta', pk=conta_id)

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
def s3_presigned_url(abs_key: str, expires_in: int = 600, *, filename: str | None = None, content_type: str | None = None, inline: bool = True) -> str:
    """URL pré-assinada S3, com Content-Disposition/Type opcionais."""
    params = {"Bucket": AWS_BUCKET, "Key": abs_key}
    if inline:
        dispo = 'inline'
        if filename:
            dispo = f'inline; filename="{filename}"'
        params["ResponseContentDisposition"] = dispo
    if content_type:
        params["ResponseContentType"] = content_type

    return _s3_client().generate_presigned_url(
        "get_object",
        Params=params,
        ExpiresIn=expires_in,
    )

from urllib.parse import urlencode

def cloudfront_signed_url_with_inline(rel_key: str, expires_in: int = 600, *, filename: str | None = None, content_type: str | None = None) -> str | None:
    """
    Gera URL CF assinada e acrescenta query para inline, se sua dist. encaminhar
    response-content-*. Se não encaminhar, o S3 presign já resolve.
    """
    if not CF_DOMAIN:
        return None

    base_url = f"https://{CF_DOMAIN}/{rel_key}"
    signer = _get_cf_signer()
    if not signer:
        # distribuição pública
        q = {}
        if content_type:
            q["response-content-type"] = content_type
        if filename:
            q["response-content-disposition"] = f'inline; filename="{filename}"'
        return base_url + (("?" + urlencode(q)) if q else "")

    from datetime import datetime, timedelta, timezone as tz
    exp = datetime.now(tz=tz.utc) + timedelta(seconds=expires_in)
    signed = signer.generate_presigned_url(base_url, date_less_than=exp)

    q = {}
    if content_type:
        q["response-content-type"] = content_type
    if filename:
        q["response-content-disposition"] = f'inline; filename="{filename}"'
    if q:
        glue = "&" if "?" in signed else "?"
        signed = signed + glue + urlencode(q)

    return signed


@login_required
def baixar_anexo(request, pk):
    anexo = get_object_or_404(Anexo.objects.select_related('base', 'conta'), pk=pk)
    if not (request.user.is_superuser or request.user.bases.filter(pk=anexo.base_id).exists()):
        return HttpResponseForbidden('Sem permissão para este anexo.')

    rel_key = anexo.arquivo.name
    if not rel_key:
        messages.error(request, "Arquivo não encontrado para este anexo.")
        return redirect('editar_conta', pk=anexo.conta_id)

    abs_key = _rel_to_abs_key(rel_key)

    filename = (anexo.nome_original or anexo.filename or "arquivo")
    ctype    = (anexo.content_type or None)

    try:
        url = cloudfront_signed_url_with_inline(rel_key, 600, filename=filename, content_type=ctype)

        if not url:
            url = s3_presigned_url(abs_key, 600, filename=filename, content_type=ctype, inline=True)

        return redirect(url)
    except Exception as e:
        logger.exception("Erro ao gerar URL do anexo %s: %s", pk, e)
        messages.error(request, "Não foi possível gerar a URL do anexo.")
        return redirect('editar_conta', pk=anexo.conta_id)
