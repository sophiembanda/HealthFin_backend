from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

def csrf_exempt(view):
    view.csrf_exempt = True
    return view
