from rest_framework import generics
from rest_framework.response import Response
from rest_framework.views import APIView


class SecurityEventListCreateView(generics.ListCreateAPIView):
    queryset = []


class AlertListView(generics.ListAPIView):
    queryset = []


class AlertSummaryView(APIView):
    def get(self, request):
        return Response({})
