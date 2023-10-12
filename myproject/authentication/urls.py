from django.urls import path
from .views import TokenViewSet

urlpatterns = [
    path('generate-token/', TokenViewSet.as_view({'post': 'generate_token'}), name='generate-token'),
    path('decode-token/<str:token>', TokenViewSet.as_view({'get': 'decode_token'}), name='decode-token'),
]
