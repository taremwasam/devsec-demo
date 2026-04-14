from django.urls import path
from . import views

app_name = 'taremwa'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('profile/', views.profile, name='profile'),
    path('profile/<int:user_id>/', views.view_profile, name='view_profile'),
    path('change-password/', views.change_password, name='change_password'),
    
    # Staff-only routes
    path('staff/dashboard/', views.staff_dashboard, name='staff_dashboard'),
    path('staff/users/', views.view_all_users, name='view_all_users'),
    path('staff/delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
]
