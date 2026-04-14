from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import UserProfile


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile"""
    model = UserProfile
    can_delete = False
    fields = ('bio', 'created_at', 'updated_at')
    readonly_fields = ('created_at', 'updated_at')


class UserAdmin(BaseUserAdmin):
    """Extended User admin with profile"""
    inlines = (UserProfileInline,)


class UserProfileAdmin(admin.ModelAdmin):
    """Admin for UserProfile"""
    list_display = ('user', 'get_email', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at', 'updated_at')

    def get_email(self, obj):
        return obj.user.email
    get_email.short_description = 'Email'


# Unregister the original User admin if it was already registered
admin.site.unregister(User)

# Register the new User admin with the inline profile
admin.site.register(User, UserAdmin)

# Register UserProfile admin
admin.site.register(UserProfile, UserProfileAdmin)
