#!/usr/bin/python

# (C) Copyright IBM Corp. 2018 All Rights Reserved

from abstract_gpylib import AbstractGpylib
from logging.handlers import RotatingFileHandler, SysLogHandler
from logging import Formatter
from flask import request
import os

manifest_location = '/app/manifest.json'
logfile_location = '/store/log/app.log'


class LiveGpylib(AbstractGpylib):

    def get_manifest_location(self):
        global manifest_location
        return manifest_location

    def get_console_address(self):
        manifest = self.get_manifest_json()
        sqlguard_ip = ''
        if 'sqlguard_ip' not in manifest:
            self.log('console not defined in manifest - default to localhost',
                level='error')
            sqlguard_ip = '127.0.0.1'
        else:
            sqlguard_ip = manifest['sqlguard_ip']
        return sqlguard_ip

    def get_CSRF_token(self):
		token = ''
		if "org.apache.catalina.filters.CSRF_NONCE" in request.values:
			token=request.values["org.apache.catalina.filters.CSRF_NONCE"]
		elif 'X-CSRF-Token' in request.headers:
		    token=request.headers['X-CSRF-Token']  
		return token

    def get_tokens(self, headers, version=None):
        if headers is None:
            headers = {}
        if 'X-CSRF-Token' not in headers:
            headers['X-CSRF-Token'] = self.get_CSRF_token()
        if version is not None:
            headers['Version'] = version
        return headers

    def get_manifest_log_level(self):
        log_level = 'info'
        manifest = self.get_manifest_json()
        if 'log_level' in manifest.keys():
            log_level = manifest["log_level"]
        return log_level

    def add_log_handler(self, loc_logger):
        global logfile_location
        loc_logger.setLevel(self.map_log_level(self.get_manifest_log_level()))
        handler = RotatingFileHandler(logfile_location, mode='ab+', maxBytes=2*1024*1024, backupCount=5)
        handler.setFormatter(Formatter('%(asctime)s [%(module)s.%(funcName)s] [%(threadName)s] [%(levelname)s] - %(message)s'))
        loc_logger.addHandler(handler)
        syslogHandler = SysLogHandler(address=(self.get_console_address(), 514))
        syslogHandler.setFormatter(Formatter('%(asctime)s %(module)s.%(funcName)s: %(message)s'))
        loc_logger.addHandler(syslogHandler)
        return

    def REST(self, RESTtype, requestURL, headers=None, data=None,
             params=None, json_inst=None, version=None):
        headers = self.get_tokens(headers, version)
        fullURL = "https://" + self.get_console_address() + "/" + requestURL
        self.log("REST " + fullURL +
                  "RESTtype " + RESTtype +
                  "headers " + str(headers) +
                  "data " + str(data) +
                  "params " + str(params) +
                  "json " + str(json_inst) +
                  "version " + str(version), 'debug')
        return self.chooseREST(RESTtype)(URL=fullURL, headers=headers,
                                         data=data, params=params, json_inst=json_inst)

    def get_app_name(self):
        manifest = self.get_manifest_json()
        app_name = 'None'
        if 'name' in manifest.keys():
            app_name = str(manifest["name"])
        return app_name

    def get_app_id(self):
        manifest = self.get_manifest_json()
        app_id = '0'
        if 'app_id' in manifest.keys():
            app_id = str(manifest["app_id"])
        return app_id

    def get_app_base_url(self):
        """Get the full url through Guardium, that will proxy any request to the
        appropriate Application plugin servlet.
        """
        self.log("getAppBaseUrl>>>", 'debug')
        proxy_path = ''

        # read /app/manifest.json,
        # get 'app_id' field and concat into url format /guardapp/{app_id}/
        manifest = self.get_manifest_json()
        if 'app_id' in manifest.keys():
            app_id = str(manifest["app_id"])
            proxy_path = "/guardapp/" + app_id

        self.log("proxy_path==>" + proxy_path, 'debug')
        self.log("<<<getAppBaseUrl", 'debug')
        return proxy_path

    def root_path(self):
        """Return root path on container.

        Works for store path too, since /app/store is defined as
        symbolic link to /store (see Dockerfile).
        """
        return "/app/"

    def store_path(self):
        """Return path of store; where persistent data should be stored."""
        return ('/store')
