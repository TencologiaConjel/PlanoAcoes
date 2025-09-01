# views.py
from __future__ import annotations

import base64
import logging
import mimetypes
import os
from urllib.parse import urlencode

import boto3
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import Prefetch
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.templatetags.static import static
from django.urls import reverse  # <— use global

from .forms import ContaForm
from .models import Anexo, Base, Conta

logger = logging.getLogger(__name__)

# =============================================================================
# AWS / CloudFront
# =============================================================================

def _clean_domain(d: str | None) -> str | None:
    """
    Sanitiza o host do CloudFront:
    - remove caracteres invisíveis/BOM
    - descarta espaços, '=' e aspas
    - remove 'https?://'
    - remove barras finais
    """
    if not d:
        return None
    d = str(d)
    d = d.replace("\u200b", "").replace("\ufeff", "")  # zero-width/BOM
    d = d.strip(" \t\r\n'\"").lstrip("= ")
    d = d.replace("https://", "").replace("http://", "").strip("/")
    return d.split("/")[0] if d else None


AWS_BUCKET      = getattr(settings, "AWS_STORAGE_BUCKET_NAME", None)
AWS_REGION      = getattr(settings, "AWS_S3_REGION_NAME", "sa-east-1")
AWS_S3_LOCATION = (getattr(settings, "AWS_S3_LOCATION", "") or "").strip("/")

CF_DOMAIN_RAW = getattr(settings, "AWS_CLOUDFRONT_DOMAIN", None)
CF_DOMAIN     = _clean_domain(CF_DOMAIN_RAW)

CF_KEY_ID   = getattr(settings, "CLOUDFRONT_KEY_ID", None)
CF_PRIV_B64 = getattr(settings, "CLOUDFRONT_PRIVATE_KEY_B64", None)
CF_PRIV_PEM = getattr(settings, "CLOUDFRONT_PRIVATE_KEY", None)

S3_ANEXOS_ROOT = getattr(settings, "S3_ANEXOS_ROOT", "anexos_v2")

try:
    from botocore.signers import CloudFrontSigner
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception:  # libs ausentes em dev/local
    CloudFrontSigner = None

from itertools import groupby

def _group_by_month(qs):
    """[{ 'label': '09/2025', 'contas': [Conta, ...] }, ...]"""
    itens = list(qs.order_by('-data', '-criado_em'))
    grupos = []
    for key, it in groupby(itens, key=lambda c: c.data.strftime('%Y-%m')):
        contas = list(it)
        label = contas[0].data.strftime('%m/%Y')  # ex.: 09/2025
        grupos.append({'label': label, 'contas': contas})
    return grupos

def _s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=getattr(settings, "AWS_ACCESS_KEY_ID", None),
        aws_secret_access_key=getattr(settings, "AWS_SECRET_ACCESS_KEY", None),
        region_name=AWS_REGION,
    )


_CF_SIGNER = None
def _get_cf_signer():
    """Cria/retorna o signer do CloudFront se houver config válida."""
    global _CF_SIGNER
    if _CF_SIGNER is not None:
        return _CF_SIGNER

    if not (CF_DOMAIN and CF_KEY_ID and (CF_PRIV_PEM or CF_PRIV_B64) and CloudFrontSigner):
        _CF_SIGNER = None
        if CF_DOMAIN:
            logger.info("CloudFront sem assinatura (chave não configurada). Usando domínio %s", CF_DOMAIN)
        else:
            logger.info("CF_DOMAIN ausente. Fallback para S3 presign.")
        return None

    pem = CF_PRIV_PEM
    if not pem and CF_PRIV_B64:
        pem = base64.b64decode(CF_PRIV_B64).decode("utf-8")

    def rsa_signer(message: bytes):
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        return key.sign(message, padding.PKCS1v15(), hashes.SHA1())

    _CF_SIGNER = CloudFrontSigner(CF_KEY_ID, rsa_signer)
    logger.info("CloudFront signer inicializado para domínio %s", CF_DOMAIN)
    return _CF_SIGNER


def _rel_to_abs_key(rel_key: str) -> str:
    """Converte chave RELATIVA em chave ABSOLUTA aplicando Origin Path (se houver)."""
    return f"{AWS_S3_LOCATION}/{rel_key}" if AWS_S3_LOCATION else rel_key


def s3_presigned_url(
    abs_key: str,
    expires_in: int = 600,
    *,
    filename: str | None = None,
    content_type: str | None = None,
    inline: bool = True,
) -> str:
    """URL pré-assinada (S3) com Content-Disposition/Type opcionais."""
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


def cloudfront_signed_url_with_inline(
    rel_key: str,
    expires_in: int = 600,
    *,
    filename: str | None = None,
    content_type: str | None = None,
) -> str | None:
    """
    Gera URL do CloudFront (assinada se chave configurada).
    Se a distribuição encaminha as query params ao S3, inclui response-content-*.
    """
    if not CF_DOMAIN:
        return None

    base_url = f"https://{CF_DOMAIN}/{rel_key}"
    signer = _get_cf_signer()

    if not signer:
        # Distribuição pública (sem assinatura)
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


def _bases_do_usuario(user):
    try:
        return user.bases.all()
    except Exception:
        return Base.objects.none()


def _resolver_base_para_request(request):
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
    anexos_qs = Anexo.objects.only(
        'id', 'arquivo', 'nome_original', 'content_type', 'tamanho',
        'criado_em', 'conta_id', 'base_id'
    )

    if request.user.is_superuser:
        base_atual = _resolver_base_para_request(request)
        qs = Conta.objects.select_related('base')
        if base_atual:
            qs = qs.filter(base=base_atual)
    else:
        bases_user = _bases_do_usuario(request.user)
        qs = Conta.objects.select_related('base').filter(base__in=bases_user)

    return qs.prefetch_related(Prefetch('anexos', queryset=anexos_qs)).order_by('-data', '-criado_em')


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
            messages.error(request, 'Senha incorreta.')
        else:
            messages.error(request, 'Usuário não encontrado.')

    return render(request, 'login.html')


@login_required
def dashboard(request):
    base_atual = _resolver_base_para_request(request)
    contas = _contas_queryset_para_dashboard(request)
    bases = Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user)
    contas_grupos = _group_by_month(contas)
    return render(request, 'dashboard.html', {
        'contas': contas,
        'contas_grupos': contas_grupos,
        'base_atual': base_atual,
        'bases': bases,
    })


@login_required
def cadastrar_conta(request):
    base_atual = _resolver_base_para_request(request)

    if request.method == 'POST':
        form = ContaForm(request.POST)
        files = request.FILES.getlist('anexos')
        if form.is_valid():
            conta = form.save(commit=False)
            conta.base = base_atual

            if not conta.base:
                form.add_error(None, 'Você não está vinculado a nenhuma base. Peça para um administrador configurar seu acesso.')
            else:
                conta.save()
                for f in files:
                    if not f:
                        continue
                    Anexo.objects.create(
                        base=conta.base,
                        conta=conta,
                        arquivo=f,
                        nome_original=getattr(f, 'name', ''),
                        uploaded_by=request.user,
                    )
                messages.success(request, f'Conta "{conta.titulo}" cadastrada com sucesso!')
                return redirect('dashboard')  
        else:
            messages.error(request, 'Erro ao cadastrar conta. Verifique os dados informados.')
    else:
        form = ContaForm()

    bases = Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user)
    return render(request, 'cadastrar.html', {'form': form, 'bases': bases, 'base_atual': base_atual})


@login_required
def editar_conta(request, pk):
    if request.user.is_superuser:
        conta = get_object_or_404(Conta.objects.select_related('base'), pk=pk)
    else:
        conta = get_object_or_404(
            Conta.objects.select_related('base'),
            pk=pk,
            base__in=_bases_do_usuario(request.user)
        )

    base_atual = conta.base

    if request.method == 'POST':
        form = ContaForm(request.POST, instance=conta)
        files = request.FILES.getlist('anexos')
        if form.is_valid():
            obj = form.save(commit=False)
            obj.base = conta.base
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

    bases = Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user)
    anexos = conta.anexos.all()
    return render(request, 'editar.html', {'form': form, 'conta': conta, 'bases': bases, 'base_atual': base_atual, 'anexos': anexos})


@login_required
def excluir_conta(request, pk):
    if request.user.is_superuser:
        conta = get_object_or_404(Conta, pk=pk)
    else:
        conta = get_object_or_404(Conta, pk=pk, base__in=_bases_do_usuario(request.user))

    base_atual = conta.base

    if request.method == 'POST':
        titulo_conta = conta.titulo

        for ax in list(conta.anexos.all()):
            try:
                ax.arquivo.delete(save=False)
            except Exception as e:
                logger.warning("Falha ao deletar arquivo do S3 (%s): %s", getattr(ax, "id", "?"), e)
            ax.delete()

        conta.delete()
        messages.success(request, f'Conta "{titulo_conta}" excluída com sucesso!')
        return redirect('dashboard')  

    bases = Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user)
    return render(request, 'excluir.html', {'conta': conta, 'bases': bases, 'base_atual': base_atual})


@login_required
def baixar_anexo(request, pk):
    """Redireciona para URL (CF ou S3) com Content-Disposition=inline, após validar a base."""
    anexo = get_object_or_404(Anexo.objects.select_related('base', 'conta'), pk=pk)
    if not (request.user.is_superuser or request.user.bases.filter(pk=anexo.base_id).exists()):
        return HttpResponseForbidden('Sem permissão para este anexo.')

    rel_key = anexo.arquivo.name
    if not rel_key:
        messages.error(request, "Arquivo não encontrado para este anexo.")
        return redirect('editar_conta', pk=anexo.conta_id) 

    abs_key  = _rel_to_abs_key(rel_key)
    filename = (anexo.nome_original or os.path.basename(rel_key) or "arquivo")
    ctype    = (anexo.content_type or mimetypes.guess_type(filename)[0] or None)

    try:
        url = cloudfront_signed_url_with_inline(rel_key, 600, filename=filename, content_type=ctype) \
              or s3_presigned_url(abs_key, 600, filename=filename, content_type=ctype, inline=True)
        return redirect(url)
    except Exception as e:
        logger.exception("Erro ao gerar URL do anexo %s: %s", pk, e)
        messages.error(request, "Não foi possível gerar a URL do anexo.")
        return redirect('editar_conta', pk=anexo.conta_id)  


@login_required
def excluir_anexo(request, pk):
    """Exclui o anexo (arquivo + registro), se o usuário tiver acesso à base."""
    anexo = get_object_or_404(Anexo.objects.select_related('base', 'conta'), pk=pk)
    if not (request.user.is_superuser or request.user.bases.filter(pk=anexo.base_id).exists()):
        return HttpResponseForbidden('Sem permissão para este anexo.')

    conta_id = anexo.conta_id
    if request.method == 'POST':
        try:
            anexo.arquivo.delete(save=False)
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


# --- helpers de permissão -----------------------------------------------------
def _user_can_access_base(user, base: Base) -> bool:
    if not base:
        return False
    return bool(user.is_superuser or user.bases.filter(pk=base.pk).exists())

# --- Power BI: lista e detalhe por base --------------------------------------
@login_required
def powerbi_index(request):
    """
    Lista as bases acessíveis ao usuário. Se houver apenas 1, redireciona direto.
    """
    if request.user.is_superuser:
        bases = Base.objects.filter(ativo=True).order_by("nome")
    else:
        bases = _bases_do_usuario(request.user).filter(ativo=True).order_by("nome")

    if bases.count() == 1:
        base = bases.first()
        return redirect("powerbi_base", slug=base.slug)  # <— namespace

    return render(request, "powerbi_index.html", {
        "bases": bases,
        "base_atual": _resolver_base_para_request(request),
    })


@login_required
def powerbi_base(request, slug: str):
    base = get_object_or_404(Base, slug=slug, ativo=True)

    if not _user_can_access_base(request.user, base):
        return HttpResponseForbidden("Sem permissão para esta base.")

    powerbi_url = (base.powerbi_url or getattr(settings, "POWERBI_URL", "")).strip()

    ctx = {
        "base": base,
        "powerbi_url": powerbi_url,
        "back_url": reverse('powerbi_index'),  
        "base_atual": base,
        "bases": Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user),
    }
    return render(request, "powerbi.html", ctx)


@login_required
def powerbi(request):
    base_atual = _resolver_base_para_request(request)

    if request.user.is_superuser:
        base_id = request.GET.get("base")
        if base_id:
            base_qs = Base.objects.filter(pk=base_id, ativo=True)
            if base_qs.exists():
                base_atual = base_qs.first()

    if not base_atual:
        return redirect("powerbi_index")  

    if not _user_can_access_base(request.user, base_atual):
        return HttpResponseForbidden("Sem permissão para esta base.")

    return redirect("powerbi_base", slug=base_atual.slug)  


@login_required
def logo_base(request, base_id: int):
    base = get_object_or_404(Base, pk=base_id)

    if not (request.user.is_superuser or request.user.bases.filter(pk=base_id).exists()):
        return HttpResponseForbidden('Sem permissão para a logo desta base.')

    if not base.logo:
        return redirect(static('img/logo-default.png'))

    rel_key = base.logo.name
    abs_key = _rel_to_abs_key(rel_key)

    filename = os.path.basename(rel_key)
    ctype = getattr(getattr(base.logo, "file", None), "content_type", None) \
            or mimetypes.guess_type(filename)[0] or "image/png"

    try:
        url = cloudfront_signed_url_with_inline(rel_key, 600, filename=filename, content_type=ctype)
        if not url:
            url = s3_presigned_url(abs_key, 600, filename=filename, content_type=ctype, inline=True)
        return redirect(url)
    except Exception as e:
        logger.exception("Erro ao assinar URL da logo da base %s: %s", base_id, e)
        return redirect(static('img/logo-default.png'))


def base_context(request):
    context = {}
    if request.user.is_authenticated:
        base_atual = _resolver_base_para_request(request)
        context['base_atual'] = base_atual

        if base_atual and base_atual.logo:
            context['logo_url'] = reverse('logo_base', args=[base_atual.id])  # <— namespace
        else:
            context['logo_url'] = static('img/logo-default.png')
    return context
