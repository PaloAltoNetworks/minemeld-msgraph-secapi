def prototypes():
    import os

    return os.path.join(os.path.dirname(__file__), 'prototypes')


def webui_blueprint():
    from minemeld.flask import aaa  #pylint: disable=E0401

    return aaa.MMBlueprint('microsoftGSAWebui', __name__, static_folder='webui', static_url_path='')
