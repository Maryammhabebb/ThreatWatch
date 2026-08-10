from django.urls import path

from security import views


urlpatterns = [
    path("events/", views.SecurityEventListCreateView.as_view(), name="event-list-create"),
    path("alerts/", views.AlertListView.as_view(), name="alert-list"),
    path("alerts/summary/", views.AlertSummaryView.as_view(), name="alert-summary"),
]
