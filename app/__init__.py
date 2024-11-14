__author__ = 'IBM'

# (C) Copyright IBM Corp. 2018 All Rights Reserved

import json
import os.path
import re
import sys
from flask import Flask
from flask import send_from_directory, render_template, request

from gpylib import gpylib

app = Flask(__name__)
# Create log here to prevent race condition when importing views
gpylib.create_log()

gpylib.register_jsonld_endpoints()

from app import views


@app.route('/debug')
def debug():
    log_loc = gpylib.get_store_path('log/')
    return send_from_directory(log_loc, 'app.log')


@app.route('/debug_view')
def debug_view():
    log_loc = gpylib.get_store_path('log/app.log')
    debug_content = open(log_loc).read()
    log_loc = os.path.dirname(os.path.join(
        os.path.dirname(__file__), 'templates/debug.html'))
    if not os.path.exists(log_loc):
        os.makedirs(log_loc)
    with open(os.path.join(
        os.path.dirname(__file__), 'templates/debug.html'),
            'w+') as debug_fil:
            debug_fil.writelines(debug_content)
    return render_template('debug.html', debug_content=debug_content)


@app.route('/resources/<path:filename>')
def send_file(filename):
    gpylib.log(" >>> route resources >>>")
    gpylib.log(" filename=" + filename)
    gpylib.log(" app.static_folder=" + app.static_folder)
    gpylib.log(" full file path =" + app.static_folder +
               '/resources/' + filename)
    return send_from_directory(app.static_folder, 'resources/'+filename)


@app.route('/log_level', methods=['POST'])
def log_level():
    level = request.form['level'].upper()
    levels = ['INFO', 'DEBUG', 'ERROR', 'WARNING', 'CRITICAL']

    if any(level in s for s in levels):
        gpylib.set_log_level(request.form['level'])
    else:
        return 'level parameter missing or unsupported - ' + str(levels), 42
    return 'log level set to ' + level


# Untested or compiled code
@app.route('/react-intl/<path:requested>', methods=['GET'])
def reactIntl(requested):
    def put_in_container(container, key, value):
        key_parts = key.split(".")

        s = len(key_parts)
        l = 0

        while s > 1:
            part = key_parts[l]

            if part not in container:
                container[part] = {}

            container = container[part]
            s = s-1
            l = l+1

        container[key_parts[l]] = value

    resources = os.path.dirname(os.path.abspath(sys.argv[0])) + \
        "/app/static/resources"

    requested_language = None
    requested_locale = None

    lang_locale = re.compile("[_\\-]").split(requested)

    if len(lang_locale) == 2:
        requested_language = lang_locale[0]
        requested_locale = lang_locale[1]
    else:
        requested_language = requested
        requested_locale = None

    gpylib.log("Requested language {0}, locale {1}".format(
        requested_language, requested_locale), "DEBUG")

    result = {"locales": [], "messages": {}}
    for f in os.listdir(resources):
        bundle_lang = f.split("_")

        """This will be either application_<lang>.properties,
        in which case we have 2 parts,
        or application_<lang>_<locale>.properties, which is 3 parts"""
        locale = None
        if len(bundle_lang) == 2:
            language = bundle_lang[1].split(".")[0]
        else:
            language = bundle_lang[1]
            locale = bundle_lang[2].split(".")[0]

        gpylib.log("Bundle {0} language {1}, locale {2}".format(
            f, language, locale), "DEBUG")

        if language == requested_language:
            filepath = os.path.join(resources, f)

            if os.path.isfile(filepath):
                with open(filepath) as thefile:

                    lang = {}

                    for line in thefile:
                        line = line.strip()
                        if len(line) > 0:
                            key_value = line.split("=")
                            put_in_container(
                                lang,
                                key_value[0].strip(),
                                key_value[1].decode('unicode-escape'))

                    if locale is None:
                        result["locales"].append(language)
                    else:
                        result["locales"].append(language + "_" + locale)

                    result["messages"].update(lang)

    return json.dumps(result)


@app.context_processor
def override_url_for():
    """Override flask.url_for(), due to different root path on container."""
    return dict(url_for=gpylib.g_url_for)


# register the new g_url_for() method for use with Jinja2 templates
app.add_template_global(gpylib.g_url_for, 'g_url_for')
