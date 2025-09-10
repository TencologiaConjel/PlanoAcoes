from __future__ import annotations
import base64
import logging
import mimetypes
import os
from urllib.parse import urlencode
import boto3
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import Prefetch
from django.utils.timezone import localdate
from django.http import HttpResponseForbidden, JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.templatetags.static import static
from django.urls import reverse 
from django.template.loader import render_to_string
from .forms import ContaForm
from .models import Anexo, Base, Conta
import re, html
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from django.contrib.staticfiles.storage import staticfiles_storage
from django.contrib.auth.forms import SetPasswordForm

logger = logging.getLogger(__name__)

def _clean_domain(d: str | None) -> str | None:
    if not d:
        return None
    d = str(d)
    d = d.replace("\u200b", "").replace("\ufeff", "")  
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
except Exception:  
    CloudFrontSigner = None

from itertools import groupby

def _group_by_month(qs):
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
    return f"{AWS_S3_LOCATION}/{rel_key}" if AWS_S3_LOCATION else rel_key


def s3_presigned_url(
    abs_key: str,
    expires_in: int = 600,
    *,
    filename: str | None = None,
    content_type: str | None = None,
    inline: bool = True,
) -> str:
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
    if not CF_DOMAIN:
        return None

    base_url = f"https://{CF_DOMAIN}/{rel_key}"
    signer = _get_cf_signer()

    if not signer:
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


def _user_can_access_base(user, base: Base) -> bool:
    if not base:
        return False
    return bool(user.is_superuser or user.bases.filter(pk=base.pk).exists())

@login_required
def powerbi_index(request):
    if request.user.is_superuser:
        bases = Base.objects.filter(ativo=True).order_by("nome")
    else:
        bases = _bases_do_usuario(request.user).filter(ativo=True).order_by("nome")

    if bases.count() == 1:
        base = bases.first()
        return redirect("powerbi_base", slug=base.slug) 

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
            context['logo_url'] = reverse('logo_base', args=[base_atual.id])  
        else:
            context['logo_url'] = static('img/logo-default.png')
    return context

from django.shortcuts import render
from django.http import HttpResponse
from django.db.models import Q
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import inch
from datetime import datetime
from io import BytesIO
from .models import Conta 

def painel_transparencia(request):
    
    base_atual = _resolver_base_para_request(request)
    
    if request.user.is_superuser:
        if base_atual:
            contas = Conta.objects.filter(base=base_atual)
        else:
            contas = Conta.objects.all()
    else:
        bases_user = _bases_do_usuario(request.user)
        if base_atual and base_atual in bases_user:
            contas = Conta.objects.filter(base=base_atual)
        else:
            contas = Conta.objects.filter(base__in=bases_user)
    
    contas = contas.order_by('-data')
    

    mes = request.GET.get('mes')
    ano = request.GET.get('ano')
    data_inicio = request.GET.get('data_inicio')
    data_fim = request.GET.get('data_fim')
    
    if mes:
        contas = contas.filter(data__month=mes)
    
    if ano:
        contas = contas.filter(data__year=ano)
    
    if data_inicio:
        contas = contas.filter(data__gte=data_inicio)
    
    if data_fim:
        contas = contas.filter(data__lte=data_fim)
    
    bases = Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user)
    
    context = {
        'contas': contas,
        'base_atual': base_atual,
        'bases': bases,
    }
    
    return render(request, 'painel_transparencia.html', context)

import re, html
from reportlab.platypus import Paragraph

_TAG_RE = re.compile(r'</?([a-zA-Z0-9]+)(?:\s[^>]*)?>')

def _plain_text(s: str | None) -> str:
    if not s:
        return ""
    txt = html.unescape(s)
    txt = re.sub(r'<[^>]+>', '', txt)                     
    txt = txt.replace('\r\n', '\n').replace('\r', '\n')   
    txt = re.sub(r'[ \t]+', ' ', txt)                     
    return txt.strip()

def _sanitize_for_reportlab(raw: str | None) -> str:
    if not raw:
        return ""

    txt = html.unescape(raw)

    txt = re.sub(r'<table\b.*?>.*?</table\s*>', '', txt, flags=re.I | re.S)

    txt = txt.replace('\r\n', '\n').replace('\r', '\n')

    txt = re.sub(r'</?p[^>]*>', '<br/>', txt, flags=re.I)

    txt = re.sub(r'<strong[^>]*>', '<b>', txt, flags=re.I).replace('</strong>', '</b>')
    txt = re.sub(r'<em[^>]*>', '<i>', txt, flags=re.I).replace('</em>', '</i>')

    txt = re.sub(r'[\u2022\u25AA\u25E6\u25CF\u25A0\u25A1]', '- ', txt)  # • ▪ ◦ ● ■ □
    txt = re.sub(r'[\u2013\u2014]', '-', txt)                            # – —

    txt = re.sub(r'<br\s*>', '<br/>', txt, flags=re.I)

    ALLOWED = {'b', 'i', 'u', 'br', 'sup', 'sub'}
    def _keep(m):
        return m.group(0) if m.group(1).lower() in ALLOWED else ''
    txt = _TAG_RE.sub(_keep, txt)
    txt = re.sub(r'(?:<br/>\s*){3,}', '<br/><br/>', txt)

    return txt.strip()

def _safe_paragraph(text: str | None, style) -> Paragraph:
    s = text if isinstance(text, str) else ("" if text is None else str(text))
    if not s:
        s = ""
    try:
        return Paragraph(s, style)
    except Exception:
        from html import escape
        return Paragraph(escape(s), style)


from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer
from reportlab.lib.units import inch
from datetime import datetime
from reportlab.lib.pagesizes import A4, landscape
from io import BytesIO
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image as RLImage, Spacer
from django.utils import timezone
from .models import UserSecurity
import urllib.request
from urllib.parse import urlparse


@login_required
def force_password_change(request):
    sec, _ = UserSecurity.objects.get_or_create(user=request.user)
    if not sec.must_change_password:
        return redirect("dashboard")

    form = SetPasswordForm(request.user, request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        update_session_auth_hash(request, user)
        sec.must_change_password = False
        sec.last_reset_at = timezone.now()
        sec.save(update_fields=["must_change_password", "last_reset_at"])
        messages.success(request, "Senha atualizada com sucesso.")
        return redirect("dashboard")

    ctx = {
        "form": form,
        "base_atual": _resolver_base_para_request(request),
        "bases": Base.objects.all() if request.user.is_superuser else _bases_do_usuario(request.user),
    }
    return render(request, "force_password_change.html", ctx)

def _logo_flowable_from_url(url: str, *, max_w=160, max_h=60, debug_out: dict | None = None):

    if debug_out is not None:
        debug_out.clear()
        debug_out["source"] = "url"
        debug_out["url"] = url[:200]  

    from io import BytesIO
    from reportlab.platypus import Image as RLImage

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (PDF-Generator)"
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status != 200:
                if debug_out is not None:
                    debug_out["error"] = f"http-status-{resp.status}"
                return None
            data = resp.read()
    except Exception as e:
        logger.warning("Falha ao baixar logo (%s): %s", url, e)
        if debug_out is not None:
            debug_out["error"] = f"download:{e}"
        return None

    if debug_out is not None:
        debug_out["bytes"] = len(data)

    try:
        from urllib.parse import urlparse, parse_qs, unquote
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path) or None
        if parsed.query:
            q = parse_qs(parsed.query)
            disp = q.get("response-content-disposition", [None])[0]
            if disp:
                m = re.search(r'filename="?([^"]+)"?', disp, flags=re.I)
                if m:
                    filename = unquote(m.group(1))
        ctype = mimetypes.guess_type(filename or "")[0] if filename else None
    except Exception:
        filename, ctype = None, None

    ir = _imagereader_from_bytes(data, filename=filename, content_type=ctype)
    if not ir:
        if debug_out is not None:
            debug_out["error"] = "imagereader-failed"
        return None

    try:
        iw, ih = ir.getSize()
    except Exception as e:
        if debug_out is not None:
            debug_out["error"] = f"getSize:{e}"
        return None

    scale = min(max_w / float(iw or 1), max_h / float(ih or 1), 1.0)
    w, h = max(1.0, iw * scale), max(1.0, ih * scale)

    try:
        img = RLImage(BytesIO(data), width=w, height=h)
        img.hAlign = "CENTER"
        if debug_out is not None:
            debug_out.update({
                "filename": filename, "ctype": ctype, "iw": iw, "ih": ih,
                "w": w, "h": h, "scale": round(scale, 3), "status": "ok", "used": "raw"
            })
        return img
    except Exception:
        try:
            is_svg = ((filename or "").lower().endswith(".svg")) or (ctype == "image/svg+xml") or (b"<svg" in data[:400].lower())
            bio_out = BytesIO()
            if is_svg:
                import cairosvg  
                bio_out.write(cairosvg.svg2png(bytestring=data))
                bio_out.seek(0)
            else:
                from PIL import Image as PILImage
                im = PILImage.open(BytesIO(data))
                if im.mode not in ("RGB", "L"):
                    im = im.convert("RGB")
                im.save(bio_out, format="PNG", optimize=True)
                bio_out.seek(0)

            img = RLImage(bio_out, width=w, height=h)
            img.hAlign = "CENTER"
            if debug_out is not None:
                debug_out.update({
                    "filename": filename, "ctype": ctype, "iw": iw, "ih": ih,
                    "w": w, "h": h, "scale": round(scale, 3), "status": "ok", "used": "converted"
                })
            return img
        except Exception as e:
            logger.warning("Falha ao converter/criar RLImage (url): %s", e)
            if debug_out is not None:
                debug_out["error"] = f"rlimage:{e}"
            return None


def _logo_flowable_from_base(base, *, max_w=160, max_h=60, debug_out: dict | None = None):
    if debug_out is not None:
        debug_out.clear()
        debug_out["source"] = "base"

    if not base or not getattr(base, "logo", None) or not base.logo.name:
        logger.info("Base sem logo definida")
        if debug_out is not None:
            debug_out["status"] = "no-logo"
        return None

    rel_key = base.logo.name
    abs_key = _rel_to_abs_key(rel_key)
    filename = os.path.basename(rel_key)
    ctype = getattr(getattr(base.logo, "file", None), "content_type", None) \
            or mimetypes.guess_type(filename)[0] or "image/png"

    try:
        url = cloudfront_signed_url_with_inline(
            rel_key, expires_in=900, filename=filename, content_type=ctype
        ) or s3_presigned_url(
            abs_key, expires_in=900, filename=filename, content_type=ctype, inline=True
        )
    except Exception as e:
        logger.warning("Erro ao gerar URL pré-assinada p/ logo: %s", e)
        url = None

    if url:
        if debug_out is not None:
            debug_out["signed_url"] = url  
            debug_out["via"] = "signed-url"
        img = _logo_flowable_from_url(url, max_w=max_w, max_h=max_h, debug_out=debug_out)
        if img is not None:
            return img

    try:
        base.logo.open("rb")
        data = base.logo.read()
        base.logo.close()
    except Exception as e:
        logger.warning("Falha ao ler logo do storage: %s", e)
        if debug_out is not None:
            debug_out["error"] = f"storage-read:{e}"
        return None

    if debug_out is not None:
        debug_out["via"] = "storage"
        debug_out["bytes"] = len(data)

    ir = _imagereader_from_bytes(data, filename=filename, content_type=ctype)
    if not ir:
        if debug_out is not None:
            debug_out["error"] = "imagereader-failed"
        return None

    iw, ih = ir.getSize()
    scale = min(max_w / float(iw or 1), max_h / float(ih or 1), 1.0)
    w, h = max(1.0, iw * scale), max(1.0, ih * scale)

    from io import BytesIO
    from reportlab.platypus import Image as RLImage

    try:
        img = RLImage(BytesIO(data), width=w, height=h)  
        img.hAlign = "CENTER"
        if debug_out is not None:
            debug_out.update({"filename": filename, "ctype": ctype, "iw": iw, "ih": ih,
                              "w": w, "h": h, "scale": round(scale, 3), "status": "ok", "used": "raw"})
        return img
    except Exception:
        try:
            is_svg = (filename or "").lower().endswith(".svg") or ctype == "image/svg+xml"
            if is_svg:
                import cairosvg
                png = cairosvg.svg2png(bytestring=data)
                bio = BytesIO(png)
            else:
                from PIL import Image as PILImage
                im = PILImage.open(BytesIO(data))
                if im.mode not in ("RGB", "L"):
                    im = im.convert("RGB")
                bio = BytesIO()
                im.save(bio, format="PNG", optimize=True)
                bio.seek(0)

            img = RLImage(bio, width=w, height=h)
            img.hAlign = "CENTER"
            if debug_out is not None:
                debug_out.update({"filename": filename, "ctype": ctype, "iw": iw, "ih": ih,
                                  "w": w, "h": h, "scale": round(scale, 3), "status": "ok", "used": "converted"})
            return img
        except Exception as e:
            logger.warning("Falha ao converter/criar RLImage (storage): %s", e)
            if debug_out is not None:
                debug_out["error"] = f"rlimage:{e}"
            return None

def _imagereader_from_bytes(raw: bytes, *, filename: str | None = None, content_type: str | None = None):
    from io import BytesIO
    from reportlab.lib.utils import ImageReader

    if not raw or len(raw) == 0:
        logger.warning("Dados da imagem estão vazios")
        return None

    try:
        ir = ImageReader(BytesIO(raw))
        ir.getSize()  
        logger.info("Logo carregada diretamente pelo ReportLab")
        return ir
    except Exception as e:
        logger.info(f"ImageReader direto falhou: {e}, tentando conversões...")

    try:
        is_svg = (
            (filename and filename.lower().endswith(".svg"))
            or (content_type == "image/svg+xml")
            or (b"<svg" in raw[:400].lower())
        )
        if is_svg:
            logger.info("Detectado SVG, convertendo para PNG...")
            import cairosvg 
            png = cairosvg.svg2png(bytestring=raw)
            ir = ImageReader(BytesIO(png))
            ir.getSize()
            logger.info("SVG convertido para PNG com sucesso")
            return ir
    except ImportError:
        logger.warning("cairosvg não instalado, não é possível converter SVG")
    except Exception as e:
        logger.warning(f"Conversão SVG→PNG falhou: {e}")

    try:
        from PIL import Image as PILImage
        logger.info("Tentando conversão via Pillow...")
        
        bio = BytesIO(raw)
        im = PILImage.open(bio)
        
        if im.mode not in ("RGB", "L"):
            logger.info(f"Convertendo modo {im.mode} para RGB")
            im = im.convert("RGB")
            
        out = BytesIO()
        im.save(out, format="PNG", optimize=True)
        out.seek(0)
        
        ir = ImageReader(out)
        ir.getSize()
        logger.info(f"Imagem convertida via Pillow: {im.size}")
        return ir
        
    except ImportError:
        logger.warning("Pillow não instalado, não é possível converter imagem")
    except Exception as e:
        logger.warning(f"Conversão via Pillow falhou: {e}")
        
    logger.error("Todas as tentativas de conversão de imagem falharam")
    return None


BLUE_DARK   = colors.HexColor("#1f4aa8")  
BLUE_LIGHT  = colors.HexColor("#e9eefc")
GRID_LIGHT  = colors.HexColor("#cfd6e6")
GREEN_OK    = colors.HexColor("#b9dfc3")  
YELLOW_WARN = colors.HexColor("#fff3cd")  
RED_ALERT   = colors.HexColor("#f8d7da")  

styles = getSampleStyleSheet()
TITLE_CENTER = ParagraphStyle(
    "TITLE_CENTER",
    parent=styles["Heading1"],
    alignment=1,  
    fontSize=16,
    textColor=BLUE_DARK,
    spaceAfter=0,
    spaceBefore=0,
    leading=18,
)

META_LABEL = ParagraphStyle(
    "META_LABEL", parent=styles["Normal"], fontSize=7, textColor=colors.black, leading=10
)
META_VALUE = ParagraphStyle(
    "META_VALUE", parent=styles["Normal"], fontSize=8, textColor=colors.black, leading=10
)

def _status_background(value: str) -> colors.Color | None:
    if not value:
        return None
    v = value.strip().lower()
    if "conclu" in v or "finaliz" in v:
        return GREEN_OK
    if "andament" in v or "pendente" in v:
        return YELLOW_WARN
    if "atras" in v or "cancel" in v:
        return RED_ALERT
    return None

def _build_pdf_header(base_for_logo, page_width, *, titulo, meta):
    from reportlab.platypus import Table, TableStyle, Paragraph, Spacer, KeepTogether
    from reportlab.platypus.flowables import HRFlowable

    logo_flow = _logo_flowable_from_base(base_for_logo, max_w=170, max_h=60)
    if not logo_flow:
        logo_flow = Spacer(170, 60)

    meta_rows = [
        [Paragraph("<b>CÓDIGO</b>", META_LABEL), Paragraph(meta.get("codigo","—"), META_VALUE)],
        [Paragraph("Emissão Inicial", META_LABEL), Paragraph(meta.get("emi_ini","—"), META_VALUE)],
        [Paragraph("Emissão Final", META_LABEL), Paragraph(meta.get("emi_fim","—"), META_VALUE)],
        [Paragraph("<b>RESPONSÁVEL</b>", META_LABEL), Paragraph(meta.get("resp","—"), META_VALUE)],
    ]
    meta_tbl = Table(meta_rows, colWidths=[85, 115], hAlign="RIGHT")
    meta_tbl.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, GRID_LIGHT),
        ("BACKGROUND", (0,0), (-1,-1), colors.whitesmoke),
        ("ALIGN", (0,0), (0,-1), "RIGHT"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ]))

    title_flow = Paragraph(f"<b>{titulo}</b>", TITLE_CENTER)

    col_logo  = 200
    col_meta  = 210
    col_title = max(200, page_width - col_logo - col_meta)

    header_tbl = Table(
        [[logo_flow, title_flow, meta_tbl]],
        colWidths=[col_logo, col_title, col_meta],
        rowHeights=[64],
        hAlign="LEFT",
    )
    header_tbl.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (0,0), (-1,-1), 0),
    ]))

    hr = HRFlowable(width="100%", thickness=1, color=BLUE_DARK, spaceBefore=6, spaceAfter=0)

    return KeepTogether([header_tbl, hr])

@login_required
def gerar_pdf(request):
    base_atual = _resolver_base_para_request(request)

    if request.user.is_superuser:
        contas = Conta.objects.all()
        if base_atual:
            contas = contas.filter(base=base_atual)
    else:
        bases_user = _bases_do_usuario(request.user)
        if base_atual and bases_user.filter(pk=base_atual.pk).exists():
            contas = Conta.objects.filter(base=base_atual)
        else:
            contas = Conta.objects.filter(base__in=bases_user)
    contas = contas.order_by("-data")

    mes = request.GET.get("mes")
    ano = request.GET.get("ano")
    data_inicio = request.GET.get("data_inicio")
    data_fim = request.GET.get("data_fim")

    if mes and mes.isdigit():
        contas = contas.filter(data__month=int(mes))
    if ano and ano.isdigit():
        contas = contas.filter(data__year=int(ano))
    if data_inicio:
        contas = contas.filter(data__gte=data_inicio)
    if data_fim:
        contas = contas.filter(data__lte=data_fim)

    base_for_logo = base_atual
    if not base_for_logo:
        base_ids = list(contas.values_list("base_id", flat=True).distinct()[:2])
        if len(base_ids) == 1:
            base_for_logo = Base.objects.filter(pk=base_ids[0]).first()

    from reportlab.lib.pagesizes import A4, landscape
    from io import BytesIO
    buffer = BytesIO()
    PAGE_SIZE = landscape(A4)
    page_w, page_h = PAGE_SIZE
    left, right, top, bottom = 36, 36, 36, 30
    usable_w = page_w - left - right

    doc = SimpleDocTemplate(
        buffer,
        pagesize=PAGE_SIZE,
        leftMargin=left, rightMargin=right, topMargin=top, bottomMargin=bottom
    )

    elements = []

    def _determinar_datas_emissao(contas_queryset, data_inicio_param, data_fim_param, mes_param, ano_param):
        def _formatar_data_br(data_str):
            if not data_str or data_str == "—":
                return data_str
            try:
                if "/" in data_str and len(data_str.split("/")) == 3:
                    partes = data_str.split("/")
                    if len(partes[0]) == 4:  
                        return f"{partes[2]}/{partes[1]}/{partes[0]}"
                    else:  
                        return data_str
                elif "-" in data_str:
                    from datetime import datetime
                    data_obj = datetime.strptime(data_str, "%Y-%m-%d")
                    return data_obj.strftime("%d/%m/%Y")
                else:
                    return data_str
            except:
                return data_str

        if data_inicio_param and data_fim_param:
            return _formatar_data_br(data_inicio_param), _formatar_data_br(data_fim_param)
        
        if data_inicio_param and not data_fim_param:
            
            ultima_conta = contas_queryset.first()  
            data_fim_calculada = ultima_conta.data.strftime("%d/%m/%Y") if ultima_conta else _formatar_data_br(data_inicio_param)
            return _formatar_data_br(data_inicio_param), data_fim_calculada
        
        if data_fim_param and not data_inicio_param:
            primeira_conta = contas_queryset.last() 
            data_inicio_calculada = primeira_conta.data.strftime("%d/%m/%Y") if primeira_conta else _formatar_data_br(data_fim_param)
            return data_inicio_calculada, _formatar_data_br(data_fim_param)
        
        if mes_param and ano_param and mes_param.isdigit() and ano_param.isdigit():
            from datetime import datetime
            import calendar
            
            mes_int = int(mes_param)
            ano_int = int(ano_param)
            
            data_inicio_calculada = f"01/{mes_int:02d}/{ano_int}"
            
            ultimo_dia = calendar.monthrange(ano_int, mes_int)[1]
            data_fim_calculada = f"{ultimo_dia:02d}/{mes_int:02d}/{ano_int}"
            
            return data_inicio_calculada, data_fim_calculada
        
        if ano_param and ano_param.isdigit():
            ano_int = int(ano_param)
            return f"01/01/{ano_int}", f"31/12/{ano_int}"
        
        if mes_param and mes_param.isdigit():
            from datetime import datetime
            import calendar
            
            mes_int = int(mes_param)
            ano_atual = datetime.now().year
            
            data_inicio_calculada = f"01/{mes_int:02d}/{ano_atual}"
            ultimo_dia = calendar.monthrange(ano_atual, mes_int)[1]
            data_fim_calculada = f"{ultimo_dia:02d}/{mes_int:02d}/{ano_atual}"
            
            return data_inicio_calculada, data_fim_calculada
        
        if contas_queryset.exists():
            primeira_conta = contas_queryset.last()  
            ultima_conta = contas_queryset.first()  
            
            data_inicio_calculada = primeira_conta.data.strftime("%d/%m/%Y") if primeira_conta else "—"
            data_fim_calculada = ultima_conta.data.strftime("%d/%m/%Y") if ultima_conta else "—"
            
            return data_inicio_calculada, data_fim_calculada
        
        return "—", "—"

    emi_ini, emi_fim = _determinar_datas_emissao(contas, data_inicio, data_fim, mes, ano)

    responsavel = getattr(request.user, 'nome', None) or request.user.username or "—"

    meta = {
        "codigo":  request.GET.get("codigo")  or "—",
        "emi_ini": request.GET.get("emi_ini") or emi_ini,
        "emi_fim": request.GET.get("emi_fim") or emi_fim,
        "resp":    request.GET.get("resp")    or responsavel,
    }
    titulo_header = request.GET.get("titulo") or "MARCOS E EVENTOS DOS PROJETOS"
    elements.append(_build_pdf_header(base_for_logo, usable_w, titulo=titulo_header, meta=meta))
    elements.append(Spacer(1, 6))

    from datetime import datetime
    meta_style = ParagraphStyle("Meta2", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=1)
    meses_pt = {
        "1":"Janeiro","2":"Fevereiro","3":"Março","4":"Abril","5":"Maio","6":"Junho",
        "7":"Julho","8":"Agosto","9":"Setembro","10":"Outubro","11":"Novembro","12":"Dezembro"
    }
    elements.append(Paragraph(f"Dia: {datetime.now().strftime('%d/%m/%Y')} | Horas: {datetime.now().strftime('%H:%M:%S')}", meta_style))
    elements.append(Spacer(1, 8))

    if contas.exists():
        CELL_WRAP = ParagraphStyle(
            "CELL_WRAP",
            parent=styles["Normal"],
            fontSize=8,
            leading=12,
            spaceAfter=0,
            wordWrap="CJK",
        )

        headers = ["PROJETO", "TÍTULO", "DATA", "DESCRIÇÃO", "STATUS"]
        data_rows = [headers]
        status_values = []

        for c in contas:
            projeto  = _plain_text(getattr(getattr(c, "base", None), "nome", "") or "—")
            data_fmt = c.data.strftime("%d/%m/%Y") if getattr(c, "data", None) else "—"

            titulo_html = _sanitize_for_reportlab(getattr(c, "titulo", "") or "")
            desc_html   = _sanitize_for_reportlab(getattr(c, "descricao", "") or "")

            status_txt = getattr(c, "status", None) or "—"
            status_values.append(status_txt)

            data_rows.append([
                _safe_paragraph(projeto,     CELL_WRAP),
                _safe_paragraph(titulo_html, CELL_WRAP),  
                _safe_paragraph(data_fmt,    CELL_WRAP),
                _safe_paragraph(desc_html,   CELL_WRAP),  
                _safe_paragraph(status_txt,  CELL_WRAP),
            ])
        
        col_w = [
            usable_w * 0.18,  
            usable_w * 0.32,  
            usable_w * 0.10,  
            usable_w * 0.34,  
            usable_w * 0.06,  
        ]

        tbl = Table(data_rows, colWidths=col_w, repeatRows=1)
        tbl_style = [
            
            ("BACKGROUND", (0,0), (-1,0), BLUE_DARK),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,0), 9),
            ("ALIGN",      (0,0), (-1,0), "CENTER"),
            ("BOTTOMPADDING", (0,0), (-1,0), 6),
            ("FONTNAME", (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE", (0,1), (-1,-1), 9),
            ("VALIGN",   (0,1), (-1,-1), "TOP"),
            ("GRID",     (0,0), (-1,-1), 0.25, GRID_LIGHT),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.whitesmoke, colors.beige]),
            ("ALIGN", (2,1), (2,-1), "CENTER"),  
            ("ALIGN", (4,1), (4,-1), "CENTER"),  
            ("LEFTPADDING",  (0,1), (-1,-1), 6),
            ("RIGHTPADDING", (0,1), (-1,-1), 6),
            ("TOPPADDING",   (0,1), (-1,-1), 5),
            ("BOTTOMPADDING",(0,1), (-1,-1), 5),
        ]

        for r, st in enumerate(status_values, start=1):
            bg = _status_background(st)
            if bg:
                tbl_style.append(("BACKGROUND", (4, r), (4, r), bg))
                tbl_style.append(("FONTNAME",   (4, r), (4, r), "Helvetica-Bold"))

        tbl.setStyle(TableStyle(tbl_style))
        elements.append(tbl)
        elements.append(Spacer(1, 8))
        elements.append(Paragraph(f"Total de registros: {contas.count()}", styles["Normal"]))
    else:
        elements.append(Paragraph("Nenhum registro encontrado para o período selecionado.", styles["Normal"]))

    footer = ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, alignment=1, textColor=colors.grey)
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Documento gerado automaticamente.", footer))

    doc.build(elements)

    filename = "relatorio_transparencia"
    if base_for_logo:
        import re as _re
        filename += "_" + _re.sub(r"[^a-z0-9_-]+", "_", base_for_logo.slug.lower())
    from datetime import datetime as _dt
    filename += "_" + _dt.now().strftime("%Y%m%d_%H%M") + ".pdf"

    buffer.seek(0)
    resp = HttpResponse(buffer.getvalue(), content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp