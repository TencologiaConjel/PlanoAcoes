from django.contrib import admin
from django.urls import path, include
from core import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('cadastrar/', views.cadastrar_conta, name='cadastrar_conta'),
    path('editar/<int:pk>/', views.editar_conta, name='editar_conta'),
    path('excluir/<int:pk>/', views.excluir_conta, name='excluir_conta'),
    path('api/contas/', views.api_contas_json, name='api_contas'),
    path('dashpbix/', views.powerbi, name='dashpbix'),
    path("create-admin/", views.create_admin),
]