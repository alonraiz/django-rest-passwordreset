import django.dispatch

reset_password_token_created = django.dispatch.Signal(
    providing_args=["reset_password_token", "request"],
)

pre_password_reset = django.dispatch.Signal(providing_args=["user", "request"])

post_password_reset = django.dispatch.Signal(providing_args=["user", "request"])
