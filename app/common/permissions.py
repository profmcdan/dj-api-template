from rest_framework import permissions
from rest_framework.permissions import SAFE_METHODS


class IsSuperAdmin(permissions.BasePermission):
    """Allows access only to super admin users. """
    message = "Only Super Admins are authorized to perform this action."

    def has_permission(self, request, view):
        return bool(
            request.user.is_authenticated and request.user.role == 'SUPERADMIN')


class IsAdmin(permissions.BasePermission):
    """Allows access only to admin users. """
    message = "Only Admins are authorized to perform this action."

    def has_permission(self, request, view):
        return bool(
            request.user.is_authenticated and request.user.role == 'ADMIN')

