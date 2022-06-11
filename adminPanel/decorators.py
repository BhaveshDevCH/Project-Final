from Dashboard.views.utils import api_error_logic


def admin_restricted(view_function):
    def wrapper_function(request, *args, **kwargs):
        if request.user.is_staff or request.user.is_superuser:
                return view_function(request, *args, **kwargs)
        if request.user.is_anonymous:
            return api_error_logic(request, "Not Found","We can't find the page you're looking for", 404)
        else:
            return api_error_logic(request, "Not Found","We can't find the page you're looking for", 404)

    return wrapper_function