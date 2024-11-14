"""Define the application views and routes."""
__author__ = 'Joshua Klahn'

# (C) Copyright IBM Corp. 2019 All Rights Reserved

import os
from flask import send_from_directory, render_template, request, redirect, url_for
from app import app
from guard_cli import GuardCLI
from grdlib.GrdConnection import GrdConnection
from grdlib.GRDApi import GRDApi
from gpylib import gpylib
from re import match
from socket import error as socket_error

logger = gpylib.log


try:
    grd_connection = GrdConnection()
    grd_api = GRDApi(grd_connection)
except KeyError as e:
    logger('Invalid credentials for app install. '
           'Please stop the app and run "Update Credentials" and start the app again.')

cli_host = None
cli_session = None
cli_password = ""
fileserver_on_cli_session = None
file_sever_on = False
fileserver_source_ip = ""
file_server_link = None
errors = {}
errors_display_count = 0
csrf_token = ""
is_local = None
old_installed_patches_list = []
appliance_type = None
release_version = None
appliance_ip = None


def get_csrf_token():
    global csrf_token
    global csrf_token_last

    if gpylib.is_sdk():
        # dummy value just to ensure that app is passing it around
        return '0123456789-0123456789'
    else:
        csrf_now = request.args.get('org.apache.catalina.filters.CSRF_NONCE')

        if csrf_now:
            csrf_token = csrf_now

            return csrf_token

        else:  # if None
            return csrf_token  # Return whatever the last csrf token was


def check_error_display_count():
    global errors_display_count
    global errors

    if errors_display_count >= 1:
        errors = {}  # reset error logs so they are not displayed again
        errors_display_count = 0

    else:
        errors_display_count +=1


def gen_cli_session():
    global cli_session

    if cli_session:
        cli_session.close()

    try:
        cli_session = GuardCLI(host=cli_host,
                               port=22,
                               username="cli",
                               password=cli_password)
    except Exception as e:
        raise Exception(e)


@app.route('/')
@app.route('/index')
def index():

    global old_installed_patches_list

    if cli_session is None:
        logger('No active CLI session.  Redirecting to login page.')
        return render_template("login.html",
                               crsf_token=get_csrf_token())
    else:

        try:
            logger('Getting patch data via CLI...')
            cli_session.get_transport().send_ignore()  # Dummy packet to test the connection

            # Patch data collection
            installed_patches_list = cli_session.get_installed_patches()

            if not installed_patches_list:  # In case installed patches list can't be pulled for some reason
                installed_patches_list = old_installed_patches_list

            else:
                old_installed_patches_list = installed_patches_list

            gpu_level = cli_session.get_highest_gpu_level_installed(installed_patches_list)
            all_updates_list = cli_session.get_all_available_updates_json()
            patches_available_install = cli_session.get_available_patches_for_install(installed_patches_list)
            scheduled_patch_list = cli_session.get_scheduled_patches(installed_patches_list)
            missing_patches_list = cli_session.check_for_available_updates(
                installed_gpu_level=gpu_level, installed_release_version=release_version,
                all_updates_list=all_updates_list, installed_patches=installed_patches_list)


            check_error_display_count()

            return render_template("index.html",
                                   all_updates=all_updates_list,
                                   missing_patches_list=missing_patches_list,
                                   release_version=release_version,
                                   gpu_level=gpu_level,
                                   file_sever_on=file_sever_on,
                                   file_server_link=file_server_link,
                                   fileserver_source_ip=fileserver_source_ip,
                                   errors=errors,
                                   patches_available_install=patches_available_install,
                                   installed_patches_list=installed_patches_list,
                                   crsf_token=get_csrf_token(),
                                   appliance_ip=appliance_ip,
                                   scheduled_patch_list=scheduled_patch_list,
                                   appliance_type=appliance_type
                               )
        except IOError as e:
            logger(str(e))
            return render_template("login.html",
                                   error='Session timed out. Please login again.',
                                   crsf_token=get_csrf_token())

        except Exception as e:
            logger(str(e))
            return render_template("login.html",
                                   error='Unknown exception: ' + str(e),
                                   crsf_token=get_csrf_token())


@app.route('/login', methods=['GET', 'POST'])
def login():
    global cli_host
    global cli_password
    global is_local
    global file_server_link
    global release_version
    global appliance_type
    global cli_session
    global appliance_ip

    cli_host = None
    cli_password = None
    error = None
    file_server_link = None
    release_version = None
    appliance_type = None
    appliance_ip = None

    if request.method == 'POST':

        try:
            cli_password = request.form['password']

            if 'localcheck' in request.form:
                try:
                    cli_host = match(r'https://(.*):', grd_connection.url).group(1)  # Use local guardium instance IP

                except (IndexError, NameError):
                    error = 'App cannot establish a connection with Guardium API. ' \
                            'Stop the app and run Update Credentials.'
                    logger(str(error))
                    return render_template('login.html',
                                           error=error,
                                           crsf_token=get_csrf_token())

                is_local = True
            else:
                is_local = False
                cli_host = request.form['hostip']

        except KeyError as e:
            error = 'login POST request is missing form values.'
            logger(str(e))
            logger('POST request form values:' + str(request.form))
            return render_template('login.html',
                                   error=error,
                                   crsf_token=get_csrf_token())

        try:
            logger('Trying to open SSH session with: ' + str(cli_host))

            gen_cli_session()

            # Data collection only once per session
            appliance_ip, file_server_link = cli_session.build_file_server_link()
            release_version = cli_session.get_release_version()
            appliance_type = cli_session.get_appliance_type()

            return index()

        except Exception as e:
            logger(str(e))
            return render_template('login.html',
                                   error=e,
                                   crsf_token=get_csrf_token())

    # if request.method == 'GET':
    return render_template('login.html',
                           error=error,
                           crsf_token=get_csrf_token())


@app.route('/startfileserver', methods=['POST'])
def startfileserver():
    global fileserver_source_ip
    global file_sever_on
    global fileserver_on_cli_session
    global cli_session
    global errors
    global errors_display_count

    try:
        # start a new instance of ssh so the fileserver doesn't shutdown
        fileserver_source_ip = request.form['source-ip']
        fileserver_on_cli_session = cli_session

        fileserver_on_cli_session.start_file_server(fileserver_source_ip, timeout=3600)

        cli_session = GuardCLI(host=cli_host,
                               port=22,
                               username="cli",
                               password=cli_password)

        errors['fileserver'] = None
        file_sever_on = True

    except Exception as e:
        file_sever_on = False
        errors_display_count = 0
        errors['fileserver'] = str(e)

    return index()


@app.route('/stopfileserver', methods=['POST'])
def stopfileserver():
    global file_sever_on
    global fileserver_on_cli_session

    try:
        fileserver_on_cli_session.stop_file_server()
        fileserver_on_cli_session.close()

    except Exception as e:
        logger(str(e))
        # connection is closed
        # return render_template("login.html",
        #                        error='CLI connection timed out. Please login again.',
        #                        crsf_token=get_csrf_token())

    fileserver_on_cli_session = None
    file_sever_on = False

    return index()


@app.route('/refresh', methods=['POST'])
def refresh():

    return index()


@app.route('/installpatch', methods=['POST'])
def installpatch():
    global patch_installing
    global errors_display_count

    errors['patch_install'] = None
    schedule_str = ''
    schedule_date = ''
    schedule_time = ''

    try:
        patch_number = str(request.form['number'])

        if 'date' in request.form:  # Scheduled Install
            schedule_date = str(request.form['date'])
            schedule_time = str(request.form['time'])

            # Proper format for grdapi patch_install "2019-11-13 12:00:00"
            schedule_str = schedule_date + ' ' + schedule_time + ':00'

            logger('Scheduling install of patch ' + patch_number)
            logger('Scheduled date/time:' + schedule_str)

        else:
            logger('Starting install of patch ' + patch_number)

        # Use the grdapi in CLI to install the patch
        result = cli_session.grdapi_install_patch(patch_number=patch_number, scheduled_date=schedule_str)

        if result is not True:
            logger(str(result))
            errors_display_count = 0
            errors['patch_install'] = result
        else:
            logger('Patch "' + patch_number + '" successfully submitted.')

        logger('Verifying patch install is in "requested" status...')
        # Check if 'requested' status in Installed Patches
        scheduled = False
        counter = 0
        while counter < 4 and scheduled is False:
            scheduled_patches = cli_session.get_scheduled_patches()
            for patch in scheduled_patches:
                if patch['number'] == patch_number:
                    scheduled = True
                    logger('Verified install request.')
                    break
            counter += 1

        if scheduled is False:
            raise Exception('Install request for ' + patch_number + ' failed.  This patch is already installed or'
                                                                    ' cannot be installed on this appliance.')

    except Exception as e:
        logger(str(e))
        errors_display_count = 0
        errors['patch_install'] = str(e)

    return index()


@app.route('/deletepatch', methods=['POST'])
def deletepatch():
    global errors_display_count
    global old_installed_patches_list
    global cli_session

    errors['patch_delete'] = None

    patch_number = request.form['number']

    try:
        logger('Deleting scheduled patch ' + str(patch_number))

        result = cli_session.delete_scheduled_patch(str(patch_number))

        if result is not True:
            logger(str(result))
            errors_display_count = 0
            errors['patch_delete'] = result
        else:
            logger('Patch "' + patch_number + '" patch install schedule successfully deleted.')

            # Remove the patch from the list of old installed patches, in case it's used
            old_installed_patches_list[:] = [d for d in old_installed_patches_list if d.get('number') != patch_number]

    except Exception as e:
        logger(str(e))
        errors_display_count = 0
        errors['patch_delete'] = str(e)

    # start a new CLI session after deleting patch (otherwise we get crashes/bugs)
    gen_cli_session()

    return index()



@app.route('/favicon.ico')
def favicon():
    """Define IBM Security icon for browser tab."""
    return send_from_directory(
        os.path.join(app.root_path, 'static'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon')
