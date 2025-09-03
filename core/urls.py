from django.contrib import admin
from django.urls import path, include
from core import views

namespace='core'

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('cadastrar/', views.cadastrar_conta, name='cadastrar_conta'),
    path('editar/<int:pk>/', views.editar_conta, name='editar_conta'),
    path('excluir/<int:pk>/', views.excluir_conta, name='excluir_conta'),
    path('api/contas/', views.api_contas_json, name='api_contas'),
    path('financeiro/', views.powerbi, name='dashboard_financeiro'),
    path('anexos/<int:pk>/baixar/', views.baixar_anexo, name='baixar_anexo'),
    path('anexos/<int:pk>/excluir/', views.excluir_anexo, name='excluir_anexo'),
    path('bases/<int:base_id>/logo/', views.logo_base, name='logo_base'),
    path("dashboards/", views.powerbi_index, name="powerbi_index"),
    path("dashboards/<slug:slug>/", views.powerbi_base, name="powerbi_base"),
    path('painel/', views.painel_transparencia, name='painel_transparencia'),
    path('gerar-pdf/', views.gerar_pdf, name='gerar_pdf'),


]