# werkzeug_patch.py
try:
    from werkzeug.urls import url_quote
except ImportError:
    from werkzeug.urls import quote as url_quote
    import werkzeug.urls
    werkzeug.urls.url_quote = url_quote