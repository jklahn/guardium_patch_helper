# (C) Copyright IBM Corp. 2018 All Rights Reserved

import copy
import requests
import ast
import json
import os
import subprocess
from cryptography.fernet import Fernet
# If you want to see logs, uncomment import below in your app workspace,
# and uncomment gpylib.log calls.
# from app import gpylib


class GrdConnection:
    url = ''
    accessToken = ''
    client_secret = ''
    username = ''
    password = ''
    headers = {}


# TODO refactor (too complex and unpredictable). try overloading, if possible
    def __init__(self, GMachineIP=None, GMachinePort='8443',
                 _username=None, _password=None,
                 _client_secret=None, _client_id=None,
                 workspace=None, config_dictionary=None):
        if (config_dictionary is None):
            # read config from file
            filepath = ".guard_config"
            if workspace is not None:
                filepath = os.path.join(workspace, filepath)

            key = os.environ["GUARD_CONFIG_KEY"]
            f = Fernet(str(key))
            with open(filepath, "r") as config_file:
                config_dictionary = json.loads(f.decrypt(config_file.read()))
        else:
            # use config_dictionary
            pass

        printDict = copy.deepcopy(config_dictionary)
        printDict['gui_password'] = printDict[
            'gui_password'][:2] + "********"
        printDict['client_secret'] = printDict[
            'client_secret'][:2] + "********"
        print 'guard_config contains: ' + str(printDict)

        if GMachineIP is None:
            # on Guardium Machine, use default docker0 getaway.
            # TODO do once (save os.environ(...))
            if os.getenv("GUARD_APPFW_SDK") == "true" or \
               os.getenv("DOCKER_LOCAL") == "true":
                GMachineIP = config_dictionary['hostname']
                print "Creating connection to " + GMachineIP
                # gpylib.log("Creating connection to " + GMachineIP)
            else:
                try:
                    GMachineIP = subprocess.check_output(
                            "ip route | grep default | awk {'print $3'}",
                            shell=True).strip()
                    print ("Created connection to Guardium machine thru " +
                           " docker IP " + GMachineIP)
                    # gpylib.log("Created connection to Guardium machine thru \
                    #         docker route " + GMachineIP)
                except:
                    GMachineIP = config_dictionary['hostname']
                    print ("Could not get docker IP using 'ip route'" +
                           " (not Guardium machine?);" +
                           " Creating connection to " + GMachineIP)
                    # gpylib.log("Could not get docker IP using 'ip route' \
                    #             (not Guardium machine?). \
                    #              Creating connection to " + GMachineIP)
                    pass

        if GMachineIP == "":  # FIXME: If still empty ("" in grd_sdk deploy).
            GMachineIP = config_dictionary['hostname']
        if _username is None:
            _username = config_dictionary['gui_username']
        if _password is None:
            _password = config_dictionary['gui_password']
        if _client_secret is None:
            _client_secret = config_dictionary['client_secret']
        if _client_id is None:
            _client_id = config_dictionary['client_id']

        self.url = 'https://' + str(GMachineIP) + ':' + str(GMachinePort)
        print("Connection URI thru " + self.url)
        # gpylib.log("Connection URI thru " + self.url, "debug")
        self.username = str(_username)
        self.password = _password
        self.client_secret = _client_secret
        self.client_id = _client_id
        self.get_new_access_token()
        self.headers = {'Authorization': 'Bearer ' + self.accessToken, 'Content-Type': 'application/json'}

    def get_new_access_token(self):
        data = [
            ('client_id', self.client_id),
            ('grant_type', 'password'),
            ('client_secret', self.client_secret),
            ('username', self.username),
            ('password', self.password),
        ]

        tokenURI = self.url + '/oauth/token'
        # gpylib.log("@get_new_access_token: send data " + str(data) +
        #            " to " + tokenURI, "debug")
        # res=requests.post(self.url + '/oauth/token', data=data, verify=False)
        self.accessToken = ast.literal_eval(
            json.dumps(
                requests.post(
                    tokenURI, data=data,
                    verify=False).json()))['access_token']
        # gpylib.log("accessToken: " + str(self.accessToken), "debug")


    def grd_get(self, url, params):

        response = requests.get(self.url + url, params=params, headers=self.headers, verify=False)
        return response

    def grd_post(self, url, params, multipart_data=None):
        headers = dict(self.headers)
        if multipart_data is not None:
            del headers['Content-Type']
            response = requests.post(url=self.url + url, params=params, headers=headers, files=multipart_data, verify=False)
        else:
            response = requests.post(url=self.url + url, json=params, headers=headers, verify=False)
        return response

    def grd_put(self, url, params):
        response = requests.put(url=self.url + url, json=params, headers=self.headers, verify=False)
        return response

    def grd_delete(self, url, params, data=None):
        response = requests.delete(url=self.url + url, data=data, json=params, headers=self.headers, verify=False)
        return response
