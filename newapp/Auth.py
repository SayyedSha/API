from rest_framework import permissions

class CustomPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.roles=="admin":
            return request.user.is_authenticated and request.user.issuperuser
