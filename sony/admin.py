from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import PasswordResetToken, EmailVerification

@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'code', 'created_at', 'expires_at', 'used', 'is_valid')
    list_filter = ('used', 'created_at')
    search_fields = ('user__username', 'user__email', 'token')
    readonly_fields = ('created_at',)
    
    def is_valid(self, obj):
        return obj.is_valid()
    is_valid.boolean = True
    is_valid.short_description = 'Valide'

@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'email', 'code', 'created_at', 'expires_at', 'verified', 'is_valid')
    list_filter = ('verified', 'created_at')
    search_fields = ('user__username', 'email', 'code')
    readonly_fields = ('created_at',)
    
    def is_valid(self, obj):
        return obj.is_valid()
    is_valid.boolean = True
    is_valid.short_description = 'Valide'

# Personnalisation de l'admin pour User
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'date_joined')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)

# Réenregistrer User avec l'admin personnalisé
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

# Personnalisation du header admin
admin.site.site_header = "Sony Back Administration"
admin.site.site_title = "Sony Back Admin"
admin.site.index_title = "Bienvenue dans l'administration Sony Back"