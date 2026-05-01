from django.apps import AppConfig


class TaremwaConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'taremwa'

    def ready(self):
        import taremwa.signals
