

from . import views
from django.urls import path,include



urlpatterns = [

    path('', views.home, name="home"),
    path('login/',views.login,name="login"),
    path('register/', views.register, name="register"),
    path('logout/', views.logout, name="logout"),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('patient/', views.patient, name="patient"),
    path('doctor/', views.doctor, name="doctor"),

    path('draft_list/', views.draft_list, name='draft_list'),
    path('viewblog',views.viewblog,name='viewblog'),
    path('addblog',views.addblog,name='addblog'),
    path('google-auth/', views.google_auth, name='google_auth'),
    path('google-auth-callback/', views.google_auth_callback, name='google_auth_callback'),
    path('doctor/', views.doctor, name="doctor"),
    path('doctorlist/', views.doctorlist, name="doctorlist"),
    path('confirm/', views.confirm, name="confirm"),

    path('booktoken/<int:id>/', views.booktoken, name="booktoken"),
]
