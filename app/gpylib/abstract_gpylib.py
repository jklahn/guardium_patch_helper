#!/usr/bin/python

# (C) Copyright IBM Corp. 2018 All Rights Reserved

from abc import ABCMeta, abstractmethod
import os
import sys
import requests
import logging
from flask import url_for
import json_gpylib
import json

loggerName = 'com.ibm.applicationLogger'
logger = 0

class AbstractGpylib(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_app_id(self):
        pass

    @abstractmethod
    def get_app_name(self):
        pass

    @abstractmethod
    def get_manifest_location(self):
        pass

    def RESTget(self, URL, headers, data=None,
                params=None, json_inst=None, auth=None):
        self.log("REST get issued to " + URL + " " + str(params), "debug")
        return requests.get(URL, params=params,
                            headers=headers, verify=False, auth=auth,
                            data=data, json=json_inst)

    def RESTput(self, URL, headers, data=None,
                params=None, json_inst=None, auth=None):
        self.log("REST put issued to " + URL + " " + str(params), "debug")
        return requests.put(URL, params=params,
                            headers=headers, verify=False, auth=auth,
                            data=data, json=json_inst)

    def RESTpost(self, URL, headers, data=None,
                 params=None, json_inst=None, auth=None):
        self.log("REST post issued to " + URL + " " + str(params), "debug")
        return requests.post(URL, params=params,
                            headers=headers, verify=False, auth=auth,
                            data=data, json=json_inst)

    def RESTdelete(self, URL, headers, data=None,
                   params=None, json_inst=None, auth=None):
        self.log("REST delete issued to " + URL + " " + str(params), "debug")
        return requests.delete(URL, params=params,
                            headers=headers, verify=False, auth=auth,
                            data=data, json=json_inst)

    def RESTunsupported(self, URL, headers, data=None,
                        params=None, json_inst=None, auth=None):
        self.log("REST unsupported issued to " + URL + " " + str(params) +
                 str(headers) + str(data) + str(json_inst) + str(auth), "debug")
        raise ValueError('The REST type passed is not supported')

    def chooseREST(self, RESTtype):
        RESTtype = RESTtype.upper()
        return {
            'GET': self.RESTget,
            'PUT': self.RESTput,
            'POST': self.RESTpost,
            'DELETE': self.RESTdelete,
        }.get(RESTtype, self.RESTunsupported)

    @abstractmethod
    def REST(self, RESTtype, requestURL, headers=None, data=None,
             params=None, json_inst=None, version=None):
        pass

    def choose_log_level(self, level='INFO'):
        if logger == 0:
            raise SystemError('You can not call log before logging has been initialised')

        level = level.upper()
        return {
            'INFO': logger.info,
            'DEBUG': logger.debug,
            'ERROR': logger.error,
            'WARNING': logger.warning,
            'CRITICAL': logger.critical,
            'EXCEPTION': logger.exception,
        }.get(level, logger.info)

    def map_log_level(self, log_level='INFO'):
        log_level = log_level.upper()
        return {
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'WARNING': logging.WARNING,
            'CRITICAL': logging.CRITICAL,
        }.get(log_level, logging.INFO)

    @abstractmethod
    def add_log_handler(self, loc_logger):
        pass

    def create_log(self):
        global logger
        global loggerName
        logger = logging.getLogger(loggerName)
        self.add_log_handler(logger)
        self.log("Created log " + loggerName, 'info')
        sys.stdout = LoggerWriter(logger.debug)
        sys.stderr = LoggerWriter(logger.warning)

    def set_log_level(self, log_level='INFO'):
        logger.setLevel(self.map_log_level(log_level))

    @abstractmethod
    def get_console_address(self):
        pass

    @abstractmethod
    def root_path(self):
        pass

    def get_root_path(self, relative_path):
        return os.path.join(self.root_path(), relative_path)

    @abstractmethod
    def store_path(self):
        pass

    def get_store_path(self, relative_path):
        return os.path.join(self.store_path(), relative_path)

    def to_json_dict(self, python_obj, classkey=None):
        """
        Helper function to convert a Python object into a dict
        usable with the JSON REST.
        Recursively converts fields which are also Python objects.
        @param python_obj: Python object to be converted into a dict
        @return dict object containing key:value pairs for the python
        objects fields. Useable with JSON REST.
        """
        if isinstance(python_obj, dict):
            data = {}
            for (k, v) in python_obj.items():
                data[k] = self.to_json_dict(v, classkey)
            return data
        elif hasattr(python_obj, "_ast"):
            return self.to_json_dict(python_obj._ast())
        elif hasattr(python_obj, "__iter__"):
            return [self.to_json_dict(v, classkey) for v in python_obj]
        elif hasattr(python_obj, "__dict__"):
            data = dict([(key, self.to_json_dict(value, classkey))
                         for key, value in python_obj.__dict__.iteritems()
                         if not callable(value) and not key.startswith('_')])
            if classkey is not None and hasattr(python_obj, "__class__"):
                data[classkey] = python_obj.__class__.__name__
            return data
        else:
            return python_obj

    @abstractmethod
    def get_app_base_url(self):
        pass

    @abstractmethod
    def get_CSRF_token(self):
        pass

    def g_url_for(self, endpoint, **values):
        """
        Create a method to wrap the standard Flask url_for())method,
        to include the proxied url through Guardium as a prefix to the
        short-name Flask route name
        """
        # append CSRF token to every URI;
        # needed for Gmachine security; forbidden (403) without it.
        values['org.apache.catalina.filters.CSRF_NONCE'] = \
            self.get_CSRF_token()

        url = self.get_app_base_url() + url_for(endpoint, **values)
        self.log("g_url_for==>" + url, 'debug')
        return url

    def map_notification_code(self, log_level='INFO'):
        log_level = log_level.upper()
        return {
            'INFO': "0000006000",
            'DEBUG': "0000006000",
            'ERROR': "0000003000",
            'WARNING': "0000004000",
            'CRITICAL': "0000003000",
        }.get(log_level, "0000006000")

    def log(self, message,  level='info'):
        log_fn = self.choose_log_level(level)
        log_fn("127.0.0.1 " +
               "[APP_ID/" +  self.get_app_id() + "]" +
               "[NOT:" +  self.map_notification_code(level) + "] " +
               message)

    def register_jsonld_type(self, context):
        if context is not None:
            jsonld_type = self.extract_type(context)
            self.log("Registering JSONLD type " + str(jsonld_type) , "info")
            json_gpylib.register_jsonld_type(jsonld_type, context)

    def get_jsonld_type(self, jsonld_type):
        self.log("getting JSONLD type " + str(jsonld_type) , "debug")
        return json_gpylib.get_jsonld_type(jsonld_type)

    
    def get_offense_rendering(self, offense_id, render_type):
        rendering_fn = self.choose_offense_rendering(render_type)
        return rendering_fn(offense_id)


    def get_asset_rendering(self, asset_id, render_type):
        rendering_fn = self.choose_asset_rendering(render_type)
        return rendering_fn(asset_id)

    def extract_jsonld_context(self, argument, mime_id, context_id):
        if mime_id in argument.keys() and context_id in argument.keys():
            if argument[mime_id] == 'application/json+ld':
                return argument[context_id]

    def extract_type(self, argument):
        type_id=None
        if '@context' in argument.keys():
            context=argument['@context']
            if '@type' in context.keys():
                type_id=context['@type']
            if type_id == '@id' and '@id' in context.keys():
                type_id=context['@id']
        return type_id


    def register_jsonld_endpoints(self):
        manifest = self.get_manifest_json()
        services=None
        endpoints=None
        if 'services' in manifest.keys():
            services=manifest['services']

        if services is not None:
            for service in services:
                if 'endpoints' in service.keys():
                    endpoints=service['endpoints']

        if endpoints is not None:
            for endpoint in endpoints:
                jsonld_context = None
                if 'request_mime_type' in endpoint.keys():
                    argument=endpoint
                    jsonld_context = self.extract_jsonld_context(argument, 'request_mime_type', 'request_body_type')
                    self.register_jsonld_type(jsonld_context)
                if 'response' in endpoint.keys():
                    argument = endpoint['response']
                    jsonld_context = self.extract_jsonld_context(argument, 'mime_type', 'body_type')
                    self.register_jsonld_type(jsonld_context)


    def get_manifest_json(self):
        pre_pended_manifest_location = os.path.join(self.root_path(), self.get_manifest_location())
        with open(pre_pended_manifest_location) as manifest_file:
            return json.load(manifest_file)

    def render_json_ld_type(self, jld_type, data, jld_id = None):
        return json_gpylib.render_json_ld_type(jld_type, data, jld_id)

class LoggerWriter:
    def __init__(self, level):
        # self.level is really like using log.debug(message)
        self.level = level

    def write(self, message):
        # if statement reduces the amount of newlines that are
        # printed to the logger
        if message != '\n':
            self.level(message)

    def flush(self):
        pass
        # create a flush method so things can be flushed when
        # the system wants to.
