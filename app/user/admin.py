# from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
# from django.utils.translation import gettext as _
# from .models import User, Token
#
#
# class UserAdmin(BaseUserAdmin):
#     ordering = ['email']
#     list_display = ['email', 'lastname', 'firstname', 'role']
#     search_fields = ('id', 'email', 'lastname', 'firstname', 'phone', 'role')
#     fieldsets = (
#         (None, {'fields': ('email', 'password')}),
#         (_('Personal Info'), {
#             'fields': ('lastname', 'firstname', 'phone', 'role', 'image')}),
#         (
#             _('Permissions'),
#             {'fields': ('is_active', 'is_superuser', 'verified')}
#         ),
#         (_('Important Info'), {'fields': ('last_login',)})
#     )
#     add_fieldsets = (
#         (None, {
#             'classes': ('wide',),
#             'fields': ('email', 'lastname', 'firstname', 'role', 'verified', 'password1', 'password2')
#         }),
#     )
#
#
# admin.site.register(User, UserAdmin)
# admin.site.register(Token)
