from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from taremwa.models import UserProfile


class Command(BaseCommand):
    help = 'Create groups and permissions for role-based access control'

    def handle(self, *args, **options):
        # Get or create groups
        staff_group, created = Group.objects.get_or_create(name='staff')
        instructor_group, created = Group.objects.get_or_create(name='instructor')
        
        # Get UserProfile content type
        userprofile_ct = ContentType.objects.get_for_model(UserProfile)
        
        # Create custom permissions
        view_all_profiles_perm, created = Permission.objects.get_or_create(
            codename='view_all_profiles',
            name='Can view all user profiles',
            content_type=userprofile_ct,
        )
        
        edit_other_profiles_perm, created = Permission.objects.get_or_create(
            codename='edit_other_profiles',
            name='Can edit other user profiles',
            content_type=userprofile_ct,
        )
        
        view_admin_dashboard_perm, created = Permission.objects.get_or_create(
            codename='view_admin_dashboard',
            name='Can view admin dashboard',
            content_type=userprofile_ct,
        )
        
        # Assign permissions to groups
        # Instructor: can view all profiles
        instructor_group.permissions.add(view_all_profiles_perm)
        
        # Staff: can view and edit all profiles, view admin dashboard
        staff_group.permissions.add(
            view_all_profiles_perm,
            edit_other_profiles_perm,
            view_admin_dashboard_perm
        )
        
        self.stdout.write(
            self.style.SUCCESS('Successfully created groups and permissions')
        )
        self.stdout.write(f'Created group: staff')
        self.stdout.write(f'Created group: instructor')
        self.stdout.write(f'Created permission: view_all_profiles')
        self.stdout.write(f'Created permission: edit_other_profiles')
        self.stdout.write(f'Created permission: view_admin_dashboard')
