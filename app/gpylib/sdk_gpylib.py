#!/usr/bin/python

# (C) Copyright IBM Corp. 2018 All Rights Reserved

from abstract_gpylib import AbstractGpylib
import json
import os
import os.path
import sys
import getpass
import logging
import platform
from logging.handlers import RotatingFileHandler, SysLogHandler
from logging import Formatter

dev_auth_file = ".guard_appfw.auth"
yes = ("y", "yes")
no = ("no", "n")

api_auth_user = 0
api_auth_password = 0
consoleIP = 0
handler_added = 0

manifest_location = 'manifest.json'

class SdkGpylib(AbstractGpylib):

    def get_manifest_location(self):
        global manifest_location
        return manifest_location

    def get_app_id(self):
        return "DEV_APP"

    def get_app_name(self):
        return "SDK_APP"

    def get_console_address(self):
        manifest = self.get_manifest_json()
        if 'sqlguard_ip' in manifest.keys():
            sqlguard_ip = manifest["sqlguard_ip"]
        else:
            print("What is the IP of Guardium console? "),
            print("(required to make this API call)")
            sys.stdout.flush()
            sqlguard_ip = raw_input()
            manifest['sqlguard_ip'] = sqlguard_ip
            dictionary_str = json.dumps(manifest)
            with open(os.path.join(self.root_path(), self.get_manifest_location()), "w") as manifest_file:
                manifest_file.write(dictionary_str)
        return sqlguard_ip


    def get_api_auth(self):
        auth = None
        global dev_auth_file
        global api_auth_user
        global api_auth_password
        home = os.path.expanduser("~")
        auth_file_path = os.path.join(home, dev_auth_file)
        if os.path.isfile(auth_file_path):
            print("Loading user details from file: " + str(auth_file_path))
            sys.stdout.flush()
            with open(auth_file_path) as authfile:
                auth_json = json.load(authfile)
                auth = (auth_json["user"], auth_json["password"])
        else:
            print("Guardium credentials for Guardium Appliance IP are required to make this API call:")
            if api_auth_user == 0:
                print( "User:" )
                sys.stdout.flush()
                api_auth_user = raw_input()
            if api_auth_password == 0:
                api_auth_password = getpass.getpass("Password:")
                auth_data['user'] = api_auth_user
                auth_data['password'] = api_auth_password
                print("Store credentials credentials at:" + auth_file_path)
                print("WARNING: credentials will be stored in clear.")
                print("[y/n]:")
                sys.stdout.flush()
                do_store = raw_input()
                if do_store in yes:
                    with open(auth_file_path, 'w+') as auth_file:
                        json.dump(auth_data, auth_file)
            auth = (api_auth_user, api_auth_password)
        print( "Using Auth: " + str(auth) )
        return auth

    def REST(self, RESTtype, requestURL, headers=None, data=None, params=None, json_inst=None, version=None):
        if headers is None:
            headers={}
        if version is not None:
            headers['Version'] = version
        auth = self.get_api_auth()
        fullURL = "https://" + str(self.get_console_address()) + "/" + str(requestURL)
        rest_func = self.chooseREST(RESTtype)
        return rest_func(URL=fullURL, headers=headers, data=data, auth=auth, params=params, json_inst=json_inst)

    def add_log_handler(self, loc_logger):
        global handler_added
        if 0 == handler_added:
            logfile_location = os.path.abspath(os.path.join(os.path.join(__file__, "../../.."), "store/log/app.log"))
            loc_logger.setLevel(self.map_log_level('debug'))

            log_directory = os.path.dirname(logfile_location)
            if not os.path.exists(log_directory):
                os.makedirs(log_directory)

	    if self.is_windows():
                handler = RotatingFileHandler(logfile_location, mode='ab+', maxBytes=0, backupCount=1)
            else:
                handler = RotatingFileHandler(logfile_location, mode='ab+', maxBytes=2 *1024 * 1024, backupCount=5)
            handler.setFormatter(Formatter('%(asctime)s [%(module)s.%(funcName)s] [%(threadName)s] [%(levelname)s] - %(message)s'))
            loc_logger.addHandler(handler)

            handler = logging.StreamHandler(sys.stdout)
            loc_logger.addHandler(handler)
            handler_added=1

    def root_path(self):
        return os.getenv('GUARD_APPFW_WORKSPACE', '~')

    def store_path(self):
        """Return path of store; where persistent data should be stored."""
        return os.path.join(self.root_path(), 'store')

    def get_CSRF_token(self):
    	return ''

    def get_app_base_url(self):
        return "http://localhost:5000"

    def is_windows(self):
        return 'windows' in str(platform.system()).lower()
