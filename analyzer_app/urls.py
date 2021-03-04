from django.contrib import admin
from django.urls import path
from . import views


urlpatterns = [
    path('', views.home, name='home'),
    path('displayFile', views.displayFile, name='displayFile'),
    path('updateFile', views.updateFile, name='updateFile'),
    path('saveData', views.saveData, name='saveData'),
    path('show_file_details', views.show_file_details, name='show_file_details'),
    path('showChart', views.showChart, name='showChart'),
    path('showOptions', views.showOptions, name='showOptions'),
    path('showUniqueIPs<str:pk>', views.showUniqueIPs, name='showUniqueIPs'),
    path('showVulInfo<str:pk>/<str:val>', views.showVulInfo, name='showVulInfo'),
]