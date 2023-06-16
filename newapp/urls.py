from django.urls import path,include
from .views import *

urlpatterns = [
    path('',Authentication),
    path('data',Admin),
    path('emp',Employee),
    path('list',listing),
    path('logout',logout)
]
