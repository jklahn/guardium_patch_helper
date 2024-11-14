# (C) Copyright IBM Corp. 2018 All Rights Reserved

# This file is an auto-generated wrapper module for accessing Guardium API.
from GRDApiErrorHandling import check_for_invalid_response
from collections import OrderedDict
import json


class GRDApi:
    def __init__(self, grd_connection):
        self.grd_connection = grd_connection

    def create_datasource(self,
                         type,
                         name,
                         host,
                         application,
                         description=None,
                         port=None,
                         serviceName=None,
                         user=None,
                         password=None,
                         dbName=None,
                         shared=None,
                         conProperty=None,
                         dbInstanceDirectory=None,
                         dbInstanceAccount=None,
                         customURL=None,
                         severity=None,
                         savePassword=None,
                         compatibilityMode=None,
                         useSSL=None,
                         importServerSSLcert=None,
                         useLDAP=None,
                         useKerberos=None,
                         KerberosConfigName=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_datasource_by_id(self,
                             id,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_datasource_by_id(self,
                               id,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/delete_datasource_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_datasource_by_name(self,
                                 name,
                                 newName=None,
                                 description=None,
                                 host=None,
                                 port=None,
                                 serviceName=None,
                                 user=None,
                                 password=None,
                                 dbName=None,
                                 conProperty=None,
                                 dbInstanceDirectory=None,
                                 dbInstanceAccount=None,
                                 shared=None,
                                 customURL=None,
                                 severity=None,
                                 savePassword=None,
                                 useSSL=None,
                                 importServerSSLcert=None,
                                 useLDAP=None,
                                 useKerberos=None,
                                 KerberosConfigName=None,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_datasource_by_name', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_datasource_by_id(self,
                               id,
                               newName=None,
                               description=None,
                               host=None,
                               port=None,
                               serviceName=None,
                               user=None,
                               password=None,
                               dbName=None,
                               conProperty=None,
                               dbInstanceDirectory=None,
                               dbInstanceAccount=None,
                               shared=None,
                               customURL=None,
                               severity=None,
                               savePassword=None,
                               useSSL=None,
                               importServerSSLcert=None,
                               useLDAP=None,
                               useKerberos=None,
                               KerberosConfigName=None,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_datasource_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_datasource_by_name(self,
                               name,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_datasource_by_name(self,
                                 name,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_db_drivers(self,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/db_drivers', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_db_drivers_by_details(self,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_db_drivers_by_details', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_group_by_id(self,
                          id,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/group', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_group_by_desc(self,
                            desc,
                            GroupType=None,
                            category=None,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_group_by_desc', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_group_by_id(self,
                          id,
                          GroupType=None,
                          category=None,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_group_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_group_by_desc(self,
                          desc,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/group', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_group_by_desc(self,
                            desc,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/group', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_group_members_by_id(self,
                                id,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/group_members_by_group_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_group_members_by_desc(self,
                                  desc,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/group_members_by_group_desc', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_member_to_group_by_id(self,
                                    id,
                                    member):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/group_member_by_group_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_member_to_group_by_desc(self,
                                      desc,
                                      member):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/group_member', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_member_from_group_by_desc(self,
                                        desc,
                                        member,
                                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/group_member', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_member_from_group_by_id(self,
                                      id,
                                      member,
                                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/group_member_by_group_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_group_by_id(self,
                        id,
                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/group', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_group(self,
                    desc,
                    type,
                    appid,
                    category=None,
                    classification=None,
                    hierarchical=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/group', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_hierarchical_member_to_group_by_desc(self,
                                                   desc,
                                                   member):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/hierarchical_member', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_hierarchical_member_from_group_by_desc(self,
                                                     desc,
                                                     member,
                                                     api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/hierarchical_member', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_datasourceRef_by_name(self,
                                    application,
                                    datasourceName,
                                    objName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/datasource_ref_by_name', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_datasourceRef_by_id(self,
                                  appId,
                                  datasourceId,
                                  objId):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/datasource_ref_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_datasourceRef_by_name(self,
                                    application,
                                    datasourceName,
                                    objName,
                                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/datasource_ref', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_datasourceRef_by_id(self,
                                  appId,
                                  datasourceId,
                                  objId,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/datasource_ref', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_datasourceRef_by_name(self,
                                  application,
                                  objName,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/datasource_ref', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_datasourceRef_by_id(self,
                                appId,
                                objId,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/datasource_ref', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_staps(self,
                  onlyActive=None,
                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/stap', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_inspection_engines(self,
                               stapHost,
                               type=None,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/inspection_engine', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_stap_inspection_engine(self,
                                     stapHost,
                                     protocol,
                                     client,
                                     portMin=None,
                                     portMax=None,
                                     teeListenPort=None,
                                     teeRealPort=None,
                                     connectToIp=None,
                                     excludeClient=None,
                                     procNames=None,
                                     namedPipe=None,
                                     ktapDbPort=None,
                                     dbInstallDir=None,
                                     procName=None,
                                     db2SharedMemAdjustment=None,
                                     db2SharedMemClientPosition=None,
                                     db2SharedMemSize=None,
                                     instanceName=None,
                                     informixVersion=None,
                                     encryption=None,
                                     interceptTypes=None,
                                     ieIdentifier=None,
                                     unixSocketMarker=None,
                                     priorityCount=None,
                                     dbUser=None,
                                     api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/inspection_engine', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_stap_inspection_engine(self,
                                     stapHost,
                                     type,
                                     sequence=None,
                                     waitForResponse=None,
                                     api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/inspection_engine', params=params)
        check_for_invalid_response(result)
        return result.json()

    def restart_stap(self,
                    stapHost,
                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/stap', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_stap_debug(self,
                      stapHost,
                      stapDebugOn,
                      stapDebugLevel,
                      stapDebugInterval,
                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/stap_debug', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_ktap_debug(self,
                      stapHost,
                      ktapDebugInterval,
                      ktapFunctionNames=None,
                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/stap_debug', params=params)
        check_for_invalid_response(result)
        return result.json()

    def display_stap_config(self,
                           stapHost,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/display_stap_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_stap_config(self,
                          stapHost,
                          updateValue,
                          waitForResponse=None,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/stap_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_entry_location(self,
                             entryType,
                             fileName,
                             hostName,
                             path,
                             storageSystem,
                             processDesc=None,
                             user=None,
                             password=None,
                             retention=None,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/entry_location', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_entry_location(self,
                             hostName,
                             path,
                             fileName=None,
                             newHostName=None,
                             newPath=None,
                             user=None,
                             password=None,
                             retention=None,
                             storageSystem=None,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/entry_location', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_entry_location(self,
                             hostName,
                             path,
                             fileName=None,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/entry_location', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_entry_location(self,
                           hostName,
                           path,
                           fileName=None,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/entry_location', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_cas_host_instance(self,
                                datasourceName,
                                templateSetLabel,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/cas_host_instance', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_cas_host_instance(self,
                                datasourceName,
                                templateSetLabel,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/cas_host_instance', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_cas_host_instance(self,
                                datasourceName,
                                templateSetLabel,
                                enabled,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/cas_host_instance', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_cas_host(self,
                       hostName,
                       osType,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/cas_host', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_cas_template_set(self,
                               templateSetLabel,
                               osType,
                               dbType,
                               isDefault=None,
                               isEditable=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/cas_template_set', params=params)
        check_for_invalid_response(result)
        return result.json()

    def clone_cas_template_set(self,
                              templateSetLabel,
                              clonedTemplateSetLabel,
                              api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/clone_cas_template_set', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_cas_template_set(self,
                               templateSetLabel,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/cas_template_set', params=params)
        check_for_invalid_response(result)
        return result.json()

    def clear_cas_template_set(self,
                              templateSetLabel,
                              api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/cas_template_set', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_cas_template(self,
                           templateSetLabel,
                           auditType,
                           template,
                           period=None,
                           saveData=None,
                           useMD5=None,
                           enabled=None,
                           isEditable=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/cas_template', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_cas_template(self,
                           templateId,
                           template=None,
                           period=None,
                           saveData=None,
                           useMD5=None,
                           enabled=None,
                           isEditable=None,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/cas_template', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_cas_template(self,
                           templateId,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/cas_template', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_cas_template_sets(self,
                              osType=None,
                              dbType=None,
                              api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/cas_template_set', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_cas_templates(self,
                          templateSetLabel,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/cas_template', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_cas_hosts(self,
                      osType=None,
                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/cas_host', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_cas_host_instances(self,
                               datasourceName=None,
                               hostName=None,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/cas_host_instance', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_assessment(self,
                          assessmentDescription,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/execute_assessment', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_assessment(self,
                         assessmentDescription):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/assessment', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_assessment(self,
                         assessmentDescription,
                         newDescription=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/assessment', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_assessment(self,
                         assessmentDescription):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/assessment', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_assessment_datasource(self,
                                 assessmentDescription,
                                 datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/assessment_datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_assessment_datasource(self,
                                    assessmentDescription,
                                    datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/assessment_datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_assessment_test(self,
                           assessmentDescription,
                           testDescription,
                           severity=None,
                           threshold=None,
                           exceptionsGroup=None,
                           datasourceType=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/assessment_test', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_assessment_test_by_dsId(self,
                                   assessmentDescription,
                                   datasourceType=None,
                                   severity=None,
                                   threshold=None,
                                   exceptionsGroup=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/assessment_test', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_assessment_test(self,
                              assessmentDescription,
                              testDescription,
                              datasourceType=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/assessment_test', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_assessment_test(self,
                              assessmentDescription,
                              testDescription,
                              ExternalReference,
                              severity=None,
                              datasourceType=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/assessment_test', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_available_tests(self,
                            datasourceType,
                            testDescription=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/available_test', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_assessments(self,
                        assessmentDescription=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/assessment', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_assessment_tests(self,
                             assessmentDescription=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/assessment_test', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_auditProcess(self,
                            auditProcess,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/audit_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_incidentGenProcess(self,
                                  processId,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/execute_incident_gen_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_incidentGenProcess_byDetails(self,
                                            queryName,
                                            categoryName=None,
                                            user=None,
                                            threshold=None,
                                            severity=None,
                                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/execute_incident_gen_process_by_details', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_cls_process(self,
                           processName,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/execute_cls_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_list_registered_clients(self,
):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/gim_registered_clients', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_get_available_modules(self,
                                 clientIP):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/gim_available_modules', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_list_client_params(self,
                              clientIP):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/gim_client_params', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_update_client_params(self,
                                clientIP,
                                paramName,
                                paramValue=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/gim_client_params', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_list_client_modules(self,
                               clientIP):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/gim_list_client_modules', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_load_package(self,
                        filename):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/gim_package', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_assign_bundle_or_module_to_client_by_version(self,
                                                        clientIP,
                                                        module,
                                                        moduleVersion):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/gim_client_assign', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_schedule_install(self,
                            clientIP,
                            date,
                            module=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/gim_schedule_install', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_uninstall_module(self,
                            clientIP,
                            module,
                            date=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/gim_uninstall_module', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_list_bundles(self,
):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/gim_bundle', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_assign_latest_bundle_or_module_to_client(self,
                                                    clientIP,
                                                    module):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/gim_assign_latest_bundle', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_remove_bundle(self,
                         bundlePackageName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/gim_remove_bundle', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_unassign_client_module(self,
                                  clientIP,
                                  module=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/gim_unassign_client_module', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_schedule_uninstall(self,
                              clientIP,
                              date,
                              module=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/gim_schedule_uninstall', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_appUserTranslation(self,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/app_user_translation', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_populateGroupFromQuery(self,
                                      groupDesc,
                                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/populate_group_from_query', params=params)
        check_for_invalid_response(result)
        return result.json()

    def upload_custom_data(self,
                          tableName,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/custom_data', params=params)
        check_for_invalid_response(result)
        return result.json()

    def copy_rules(self,
                  fromPolicy,
                  toPolicy,
                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/copy_rules', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_rule(self,
                   ruleDesc,
                   fromPolicy,
                   newDesc=None,
                   clientIP=None,
                   clientNetMask=None,
                   serverIP=None,
                   serverNetMask=None,
                   objectName=None,
                   sourceProgram=None,
                   dbName=None,
                   dbUser=None,
                   command=None,
                   appUserName=None,
                   dateTime=None,
                   logFlag=None,
                   exceptionType=None,
                   minCount=None,
                   continueToNext=None,
                   resetInterval=None,
                   serviceName=None,
                   osUser=None,
                   dbType=None,
                   netProtocol=None,
                   clientMac=None,
                   fieldName=None,
                   pattern=None,
                   appEventExists=None,
                   eventType=None,
                   appEventStrValue=None,
                   appEventNumValue=None,
                   appEventDate=None,
                   eventUserName=None,
                   errorCode=None,
                   severity=None,
                   category=None,
                   classification=None,
                   dataPattern=None,
                   sqlPattern=None,
                   xmlPattern=None,
                   clientIpNotFlag=None,
                   serverIpNotFlag=None,
                   objectNameNotFlag=None,
                   sourceProgramNotFlag=None,
                   dbNameNotFlag=None,
                   dbUserNotFlag=None,
                   commandNotFlag=None,
                   appUserNameNotFlag=None,
                   exceptionTypeIdNotFlag=None,
                   serviceNameNotFlag=None,
                   osUserNotFlag=None,
                   clientMacNotFlag=None,
                   fieldNameNotFlag=None,
                   errorCodeNotFlag=None,
                   replacementChar=None,
                   messageTemplate=None,
                   recordsAffectedThreshold=None,
                   matchedReturnedTreshold=None,
                   clientIpGroup=None,
                   serverIpGroup=None,
                   objectGroup=None,
                   objectCommandGroup=None,
                   objectFieldGroup=None,
                   dbUserGroup=None,
                   commandsGroup=None,
                   dbNameGroup=None,
                   sourceProgramGroup=None,
                   appUserGroup=None,
                   serviceNameGroup=None,
                   osUserGroup=None,
                   netProtocolGroup=None,
                   fieldNameGroup=None,
                   errorGroup=None,
                   appEventStrGroup=None,
                   clientProgramUserServerInstanceGroup=None,
                   quarantineMinutes=None,
                   clientInfo=None,
                   clientInfoGroup=None,
                   triggerOncePerSession=None,
                   recordRuleDescription=None,
                   magenPageUrl=None,
                   magenPageUrlGroup=None,
                   magenAddToHistory=None,
                   objectCommandNotFlag=None,
                   objectFieldNotFlag=None,
                   clientProgramUserServerInstanceNotFlag=None,
                   objectGroupAndFlag=None,
                   fieldGroupAndFlag=None,
                   commandGroupAndFlag=None,
                   magenPageUrlNotFlag=None,
                   netProtocolNotFlag=None,
                   functionCode=None,
                   cicsUserId=None,
                   transactionId=None,
                   terminalId=None,
                   programId=None,
                   fileId=None,
                   regionId=None,
                   datasetType=None,
                   functionCodeGroup=None,
                   cicsUserGroup=None,
                   transactionGroup=None,
                   terminalGroup=None,
                   programGroup=None,
                   fileGroup=None,
                   regionGroup=None,
                   imsDefinitionName=None,
                   dliCallCodes=None,
                   audit=None,
                   ddName=None,
                   serverHostNotFlag=None,
                   serverHostName=None,
                   serverHostGroup=None,
                   clientHostNotFlag=None,
                   clientHostName=None,
                   clientHostGroup=None,
                   failureCodeNotFlag=None,
                   failureCode=None,
                   failureCodeGroup=None,
                   clientProgramUserServerInstanceOsDbGroup=None,
                   clientProgramUserServerInstanceOsDbNotFlag=None,
                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def copy_rule(self,
                 ruleDesc,
                 fromPolicy,
                 toPolicy,
                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/copy_rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_rule(self,
                   ruleDesc,
                   fromPolicy,
                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_policy_rules(self,
                         policy,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def change_rule_order(self,
                         ruleDesc,
                         fromPolicy,
                         order,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/change_rule_order', params=params)
        check_for_invalid_response(result)
        return result.json()

    def policy_install(self,
                      policy,
                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/policy_install', params=params)
        check_for_invalid_response(result)
        return result.json()

    def reinstall_policy(self,
                        policy,
                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/reinstall_policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def reinstall_policy_rule(self,
                             policy,
                             ruleName,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/reinstall_policy_rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def uninstall_policy_rule(self,
                             policy,
                             ruleName,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/uninstall_policy_rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def store_stap_approval(self,
                           isNeeded,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/stap_approval', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_approved_stap_client(self,
                                stapHost,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/approved_stap_client', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_approved_stap_client(self,
                                   stapHost,
                                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/approved_stap_client', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_approved_stap_client(self,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/approved_stap_client', params=params)
        check_for_invalid_response(result)
        return result.json()

    def revoke_ignore_stap(self,
                          stapHost,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/revoke_ignore_stap', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_api_parameter_mapping(self,
                                    functionName,
                                    parameterName,
                                    domain,
                                    entityLabel,
                                    attributeLabel,
                                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/param_mapping_for_function', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_api_parameter_mapping(self,
                                    functionName,
                                    parameterName,
                                    domain,
                                    entityLabel,
                                    attributeLabel,
                                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/param_mapping_for_function', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_quarantine_allowed_until(self,
                                       serverIp,
                                       serviceName,
                                       dbUser,
                                       allowedUntil,
                                       type,
                                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/quarantine_allowed_until', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_quarantine_until(self,
                               serverIp,
                               serviceName,
                               dbUser,
                               quarantineUntil,
                               type,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/quarantine_until', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_quarantine_allowed_until(self,
                                       serverIp,
                                       serviceName,
                                       dbUser,
                                       allowedUntil,
                                       type,
                                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/quarantine_allowed_until', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_quarantine_until(self,
                               serverIp,
                               serviceName,
                               dbUser,
                               quarantineUntil,
                               type,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/quarantine_until', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_quarantine(self,
                         serverIp,
                         serviceName,
                         dbUser,
                         type,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/quarantine', params=params)
        check_for_invalid_response(result)
        return result.json()

    def stop_audit_process(self,
                          process,
                          run,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/stop_audit_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_expiration_dates_for_restored_days(self,
                                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/expiration_dates_for_restored_days', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_expiration_date_for_restored_day(self,
                                            restoredDay,
                                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/expiration_date_for_restored_day', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_expiration_date_for_restored_day(self,
                                            restoredDay,
                                            newExpDate,
                                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/expiration_date_for_restored_day', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_schedules(self,
                      jobName=None,
                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/schedules', params=params)
        check_for_invalid_response(result)
        return result.json()

    def schedule_job(self,
                    jobType,
                    cronString,
                    objectName=None,
                    startTime=None,
                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/schedule_job', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_schedule(self,
                       jobName,
                       jobGroup,
                       deleteJob=None,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/schedule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def modify_schedule(self,
                       jobName,
                       jobGroup,
                       cronString,
                       startTime=None,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/schedule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_ztap_logging_config(self,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/ztap_logging_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_ztap_logging_config(self,
                               parameter,
                               value,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/ztap_logging_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def patch_install(self,
                     patch_number,
                     patch_date=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/patch_install', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_ad_hoc_audit_and_run_once(self,
                                        reportId,
                                        isForReportRunOnce,
                                        changeParIfExist,
                                        taskParameter=None,
                                        processNamePar=None,
                                        sendToEmails=None,
                                        emailContentType=None,
                                        includeUserReceiver=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/ad_hoc_audit_and_run_once', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_ad_hoc_audit_and_run_with_name(self,
                                             reportName,
                                             isForReportRunOnce,
                                             changeParIfExist,
                                             taskParameter=None,
                                             processNamePar=None,
                                             sendToEmails=None,
                                             emailContentType=None,
                                             includeUserReceiver=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/ad_hoc_audit_and_run_once', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_autodetect_processes(self,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/autodetect_processes', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_autodetect_tasks_for_process(self,
                                         process_name,
                                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/autodetect_tasks_for_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_autodetect_process(self,
                                 process_name,
                                 run_probe_after_scan=None,
                                 use_dns=None,
                                 check_ICMP_echo=None,
                                 host_timeout=None,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/autodetect_processes', params=params)
        check_for_invalid_response(result)
        return result.json()

    def modify_autodetect_process(self,
                                 process_name,
                                 run_probe_after_scan=None,
                                 use_dns=None,
                                 check_ICMP_echo=None,
                                 host_timeout=None,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/autodetect_processes', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_autodetect_task(self,
                           process_name,
                           hosts_list,
                           ports_list,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/add_autodetect_task', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_autodetect_scans_for_process(self,
                                           process_name,
                                           portList=None,
                                           hostList=None,
                                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/autodetect_scans_for_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def execute_autodetect_process(self,
                                  process_name,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/execute_autodetect_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def stop_autodetect_process(self,
                               process_name,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/stop_autodetect_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_classifier_policy(self,
                                policyName,
                                category,
                                classification,
                                description=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/classifier_policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_classifier_policy(self,
                              policyName=None,
                              ruleName=None,
                              actionName=None,
                              recursive=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/classifier_policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_classifier_policy(self,
                                policyName,
                                category,
                                classification,
                                description=None,
                                newName=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/classifier_policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_classifier_policy(self,
                                policyName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/classifier_policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_classifier_rule(self,
                              policyName,
                              ruleName,
                              category,
                              classification,
                              ruleType,
                              description=None,
                              continueOnMatch=None,
                              columnNameLike=None,
                              compareToValuesInGroup=None,
                              compareToValuesInSQL=None,
                              dataTypes=None,
                              evaluationName=None,
                              fireOnlyWithMarker=None,
                              hitPercentage=None,
                              maxLength=None,
                              minLength=None,
                              searchExpression=None,
                              searchLike=None,
                              tableNameLike=None,
                              tableTypeSynonym=None,
                              tableTypeSystemTable=None,
                              tableTypeTable=None,
                              tableTypeView=None,
                              showUniqueValues=None,
                              uniqueValueMask=None,
                              excludeSchemaName=None,
                              excludeTable=None,
                              excludeTableColumn=None,
                              continueWithUnmatchedColumnsOnly=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/classifier_rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_classifier_rule(self,
                              policyName,
                              ruleName,
                              category,
                              classification,
                              ruleType,
                              description=None,
                              continueOnMatch=None,
                              columnNameLike=None,
                              compareToValuesInGroup=None,
                              compareToValuesInSQL=None,
                              dataTypes=None,
                              evaluationName=None,
                              fireOnlyWithMarker=None,
                              hitPercentage=None,
                              maxLength=None,
                              minLength=None,
                              searchExpression=None,
                              searchLike=None,
                              tableNameLike=None,
                              tableTypeSynonym=None,
                              tableTypeSystemTable=None,
                              tableTypeTable=None,
                              tableTypeView=None,
                              showUniqueValues=None,
                              uniqueValueMask=None,
                              excludeSchemaName=None,
                              excludeTable=None,
                              excludeTableColumn=None,
                              continueWithUnmatchedColumnsOnly=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/classifier_rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_classifier_rule(self,
                              policyName,
                              ruleName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/classifier_rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_classifier_action(self,
                                policyName,
                                ruleName,
                                actionName,
                                actionType,
                                description=None,
                                accessPolicy=None,
                                accessRuleAction=None,
                                actualMemberContent=None,
                                commandsGroup=None,
                                includeField=None,
                                includeServerIP=None,
                                notificationType=None,
                                objectFieldGroup=None,
                                objectGroup=None,
                                privacySet=None,
                                receiver=None,
                                replaceGroupContent=None,
                                severity=None,
                                ruleDescription=None,
                                SchemaGroup=None,
                                excludeObjectGroup=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/classifier_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_classifier_action(self,
                                policyName,
                                ruleName,
                                actionName,
                                actionType,
                                description=None,
                                accessPolicy=None,
                                accessRuleAction=None,
                                actualMemberContent=None,
                                commandsGroup=None,
                                includeField=None,
                                includeServerIP=None,
                                notificationType=None,
                                objectFieldGroup=None,
                                objectGroup=None,
                                privacySet=None,
                                receiver=None,
                                replaceGroupContent=None,
                                severity=None,
                                ruleDescription=None,
                                SchemaGroup=None,
                                excludeObjectGroup=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/classifier_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_classifier_action(self,
                                policyName,
                                ruleName,
                                actionName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/classifier_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_classifier_process(self,
                                 processName,
                                 policyName,
                                 datasourceNames,
                                 comprehensive=None,
                                 sampleSize=None,
                                 includeInternalTables=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/classifier_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_classifier_process(self,
                               processName=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/classifier_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_classifier_process(self,
                                 processName,
                                 policyName=None,
                                 datasourceNames=None,
                                 comprehensive=None,
                                 sampleSize=None,
                                 newName=None,
                                 includeInternalTables=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/classifier_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_classifier_process(self,
                                 processName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/classifier_process', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_classifier_datasource(self,
                                 processName,
                                 datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/classifier_datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_classifier_datasource(self,
                                    processName,
                                    datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/classifier_datasource', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_qr_definition(self,
                            definitionName,
                            dataBaseType,
                            description=None,
                            isNegateQrCond=None,
                            sampleSql=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/qr_definition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_qr_definition(self,
                            definitionName,
                            dataBaseType,
                            newName=None,
                            description=None,
                            isNegateQrCond=None,
                            sampleSql=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/qr_definition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_qr_condition(self,
                           definitionName,
                           conditionName,
                           verb=None,
                           object=None,
                           depth=None,
                           isVerbRegex=None,
                           isObjectRegex=None,
                           isForAllRuleVerbs=None,
                           isForAllRuleObjects=None,
                           order=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/qr_condition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_qr_condition(self,
                           definitionName,
                           conditionName,
                           newName=None,
                           verb=None,
                           object=None,
                           depth=None,
                           isVerbRegex=None,
                           isObjectRegex=None,
                           isForAllRuleVerbs=None,
                           isForAllRuleObjects=None,
                           order=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/qr_condition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_qr_action(self,
                        definitionName,
                        actionName,
                        description=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/qr_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_qr_action(self,
                        definitionName,
                        actionName,
                        newName=None,
                        description=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/qr_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def assign_qr_condition_to_action(self,
                                     definitionName,
                                     actionName,
                                     conditionName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/qr_condition_to_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def unassign_qr_condition_from_action(self,
                                         definitionName,
                                         actionName,
                                         conditionName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/qr_condition_to_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_qr_add_where(self,
                           definitionName,
                           actionName,
                           whereText=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/qr_add_where', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_qr_add_where_by_id(self,
                                 qrAddWhereId,
                                 whereText=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_qr_add_where_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_qr_add_where_by_id(self,
                                 qrAddWhereId):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/remove_qr_add_where_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_qr_add_where_by_id(self,
                                 qrActionId,
                                 whereText=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/create_qr_add_where_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_qr_replace_element(self,
                                 definitionName,
                                 actionName,
                                 replaceType,
                                 replaceFrom,
                                 replaceTo,
                                 isFromRegex=None,
                                 isFromAllRuleElements=None,
                                 isReplaceToFunction=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/qr_replace_element', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_qr_replace_element_byId(self,
                                      qrActionId,
                                      replaceType,
                                      replaceFrom,
                                      replaceTo,
                                      isFromRegex=None,
                                      isFromAllRuleElements=None,
                                      isReplaceToFunction=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/create_qr_replace_element_byId', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_qr_replace_element_byId(self,
                                      qrReplaceElementId,
                                      replaceFrom=None,
                                      replaceTo=None,
                                      isFromRegex=None,
                                      isFromAllRuleElements=None,
                                      isReplaceToFunction=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_qr_replace_element_byId', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_qr_replace_element_byId(self,
                                      qrReplaceElementId):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/remove_qr_replace_element_byId', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_all_qr_replace_elements(self,
                                      definitionName,
                                      actionName,
                                      replaceType=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/remove_all_qr_replace_elements', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_all_qr_replace_elements_byId(self,
                                           qrActionId,
                                           replaceType=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/remove_all_qr_replace_elements_byId', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_qr_definition(self,
                            definitionName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/qr_definition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_qr_condition(self,
                           definitionName,
                           conditionName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/qr_condition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_qr_action(self,
                        definitionName,
                        actionName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/qr_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_definitions(self,
                           definitionName=None,
                           detail=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_qr_definitions', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_condition(self,
                         definitionName,
                         conditionName=None,
                         detail=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/qr_condition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_action(self,
                      definitionName,
                      actionName=None,
                      detail=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/qr_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_condition_to_action(self,
                                   definitionName,
                                   actionName,
                                   detail=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/qr_condition_to_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_add_where(self,
                         definitionName,
                         actionName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/qr_add_where', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_add_where_by_id(self,
                               qrActionId):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_qr_add_where_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_replace_element(self,
                               definitionName,
                               actionName,
                               replaceType=None,
                               detail=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/qr_replace_element', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_qr_replace_element_byId(self,
                                    qrActionId,
                                    replaceType=None,
                                    detail=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_qr_replace_element_byId', params=params)
        check_for_invalid_response(result)
        return result.json()

    def reset_va_summary_by_id(self,
                              summaryId,
                              resetCumulativePassTo=None,
                              resetCumulativeFailTo=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/reset_va_summary_by_id', params=params)
        check_for_invalid_response(result)
        return result.json()

    def reset_va_summary_by_key(self,
                               hostName,
                               serviceName,
                               port,
                               datasourceName,
                               resetCumulativePassTo=None,
                               resetCumulativeFailTo=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/reset_va_summary_by_key', params=params)
        check_for_invalid_response(result)
        return result.json()

    def modify_va_summary_key(self,
                             useHost,
                             usePort,
                             useServiceName,
                             useDatasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/modify_va_summary_key', params=params)
        check_for_invalid_response(result)
        return result.json()

    def reset_unit_utilization_data(self,
                                   hostName,
                                   resetDate):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/reset_unit_utilization_data', params=params)
        check_for_invalid_response(result)
        return result.json()

    def show_backup_cm_ip(self,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/show_backup_cm_ip', params=params)
        check_for_invalid_response(result)
        return result.json()

    def modify_guard_param(self,
                          paramName,
                          paramValue,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/modify_guard_param', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_guard_param(self,
                       paramName,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/get_guard_param', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_rule_action(self,
                          fromPolicy,
                          ruleDesc,
                          actionName,
                          messageTemplate=None,
                          notificationType=None,
                          alertUserLoginName=None,
                          classDestination=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/rule_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_time_period(self,
                       timePeriodDescription,
                       hourFrom,
                       hourTo,
                       weekdayFrom,
                       weekdayTo,
                       contiguous=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/time_period', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_istap_status(self,
                        datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/istap_status', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_istap_config(self,
                        datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/istap_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def start_istap_monitor(self,
                           datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/start_istap_monitor', params=params)
        check_for_invalid_response(result)
        return result.json()

    def stop_istap_monitor(self,
                          datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/stop_istap_monitor', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_istap_config(self,
                           datasourceName,
                           guardium_host=None,
                           filter_user=None,
                           filter_job=None,
                           filter_tcpip=None,
                           filter_table=None,
                           filter_port=None,
                           filter_client_acct=None,
                           filter_client_appl=None,
                           filter_client_prog=None,
                           filter_client_user=None,
                           filter_client_wkstn=None,
                           filter_rdb=None,
                           filter_system_sql=None,
                           filter_audit_entry_types=None,
                           connection_timeout_sec=None,
                           remote_messages=None,
                           start_monitor=None,
                           start_user=None,
                           prevent_skipped_entries=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/istap_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_policy(self,
                     ruleSetDesc,
                     pattern=None,
                     categoryName=None,
                     logFlat=None,
                     rulesOnFlat=None,
                     securityPolicy=None,
                     baselineDesc=None,
                     isFam=None,
                     api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_rule(self,
                   ruleDesc,
                   fromPolicy,
                   ruleType,
                   classification=None,
                   category=None,
                   order=None,
                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/rule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_receiver_to_rule_action(self,
                                   ruleDesc,
                                   fromPolicy,
                                   notificationType,
                                   actionName,
                                   alertUserLoginName=None,
                                   classDestination=None,
                                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/receiver_to_rule_action', params=params)
        check_for_invalid_response(result)
        return result.json()

    def clone_policy(self,
                    policyDesc,
                    clonedPolicyDesc,
                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/clone_policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_policy(self,
                     policyDesc,
                     pattern=None,
                     categoryName=None,
                     logFlat=None,
                     rulesOnFlat=None,
                     securityPolicy=None,
                     baselineDesc=None,
                     api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_policy(self,
                     policyDesc,
                     api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_policy(self,
                   policyDesc=None,
                   detail=None,
                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/policy', params=params)
        check_for_invalid_response(result)
        return result.json()

    def audit_process_run_status(self,
                                processName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/audit_process_run_status', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_audit_process_result(self,
                                   ProcessName,
                                   ExecutionDateFrom,
                                   ExecutionDateTo):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/audit_process_result', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_alias(self,
                    groupTypeDesc,
                    dbValue,
                    aliasValue):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/alias', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_alias(self,
                    groupTypeDesc,
                    dbValue,
                    oldAliasValue,
                    newAliasValue):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/alias', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_alias(self,
                    groupTypeDesc,
                    dbValue):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/alias', params=params)
        check_for_invalid_response(result)
        return result.json()

    def must_gather(self,
                   commandsList,
                   description=None,
                   email=None,
                   runDuration=None,
                   maxLogLength=None,
                   startRun=None,
                   pmrNumber=None,
                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/must_gather', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_quick_search(self,
                            all=None,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/disable_quick_search', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_quick_search(self,
                           schedule_interval,
                           schedule_units,
                           includeViolations=None,
                           extraction_start=None,
                           schedule_start=None,
                           all=None,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/enable_quick_search', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_outliers_detection(self,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/disableOutliersDetaction', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_outliers_detection(self,
                                 schedule_interval,
                                 schedule_units,
                                 extraction_start=None,
                                 schedule_start=None,
                                 DAM_FAM=None,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/enable_outliers_detection', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_outliers_detection_agg(self,
                                      aggregator_host_name):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/disableOutliersDetectionOnAgg', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_outliers_detection_agg(self,
                                     schedule_interval,
                                     schedule_units,
                                     aggregator_host_name,
                                     extraction_start=None,
                                     schedule_start=None,
                                     DAM_FAM=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/enableOutliersDetectionOnAgg', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_advanced_threat_scanning(self,
                                        all=None,
                                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/disable_advanced_threat_scanning', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_advanced_threat_scanning(self,
                                       schedule_start=None,
                                       all=None,
                                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/enable_advanced_threat_scanning', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_threat_detection_use_case(self,
                                        case_name,
                                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/enable_threat_detection_use_case', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_threat_detection_use_case(self,
                                         case_name,
                                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/disable_threat_detection_use_case', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_threat_detection_use_case_info(self,
                                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/threat_detection_use_case_info', params=params)
        check_for_invalid_response(result)
        return result.json()

    def gim_list_unused_bundles(self,
                               includeLatest,
                               api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_unused_bundles', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_ad_hoc_audit_for_security_assessment(self,
                                                   processNamePar=None,
                                                   sendToEmails=None,
                                                   datasourcesPar=None,
                                                   includeUserReceiver=None,
                                                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/ad_hoc_audit_for_security_assessment', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_ef_mapping(self,
                         reportName,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/create_ef_mapping', params=params)
        check_for_invalid_response(result)
        return result.json()

    def modify_ef_mapping(self,
                         reportName,
                         modifyObj,
                         oldName,
                         newName,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/modify_ef_mapping', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_ef_mapping(self,
                       reportName=None,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_ef_mapping', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_ef_mapping(self,
                         reportName,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/delete_ef_mapping', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_ef_report(self,
                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_ef_report', params=params)
        check_for_invalid_response(result)
        return result.json()

    def create_fam_rule(self,
                       policyName,
                       ruleName,
                       filePath=None,
                       notfilePath=None,
                       filePathGroup=None,
                       includeSubDirectory=None,
                       removableMedia=None,
                       osUser=None,
                       osUserGroup=None,
                       notOSUser=None,
                       serverHost=None,
                       serverHostGroup=None,
                       command=None,
                       commandGroup=None,
                       actionName=None,
                       messageTemplate=None,
                       notificationType=None,
                       alertReceiver=None,
                       classDestination=None,
                       commandGroupId=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/famPolicyRule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_action_to_fam_rule(self,
                              policyName,
                              ruleName,
                              actionName,
                              command=None,
                              commandGroup=None,
                              messageTemplate=None,
                              notificationType=None,
                              alertReceiver=None,
                              classDestination=None,
                              commandGroupId=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/addActionToFAMRule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def policy_fam_rule_delete(self,
                              policyName,
                              ruleName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/famPolicyRule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_policy_fam_rule(self,
                            policyName,
                            ruleName=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/famPolicyRule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_imscheckpoint_record(self,
                                   context,
                                   agentName,
                                   logStreamName,
                                   imsName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/ims_checkpoint', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_imscheckpoint_records(self,
):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/ims_checkpoint', params=params)
        check_for_invalid_response(result)
        return result.json()

    def configure_export(self,
                        exportOlderThan,
                        ignoreOlderThan,
                        exportValues,
                        aggHost,
                        aggSecHost=None,
                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/configure_export', params=params)
        check_for_invalid_response(result)
        return result.json()

    def configure_archive(self,
                         archiveOlderThan,
                         ignoreOlderThan,
                         archiveValues,
                         protocol,
                         destHost=None,
                         targetDir=None,
                         port=None,
                         userName=None,
                         passwd=None,
                         passwdRetype=None,
                         retention=None,
                         bucketName=None,
                         accessKey=None,
                         secretKey=None,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/configure_archive', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_archive_configuration(self,
                                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/delete_archive_configuration', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_export_configuration(self,
                                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/delete_export_configuration', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_import(self,
                  state,
                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/set_import', params=params)
        check_for_invalid_response(result)
        return result.json()

    def configure_purge(self,
                       purgeAtAge,
                       purgeWithoutArchive,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/configure_purge', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_purge(self,
                     api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/disable_purge', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_definitions_data_sets(self,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/get_definitions_data_sets', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_definitions_items(self,
                             dataSet,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/get_definitions_items', params=params)
        check_for_invalid_response(result)
        return result.json()

    def rest_export_definition(self,
                              dataSet,
                              itemsNames,
                              exportToCSV=None,
                              exportToXacml=None,
                              excludeGroupMembers=None,
                              api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/export_definition', params=params)
        check_for_invalid_response(result)
        return result.json()

    def deployApplication(self,
                         file,
                         config,
                         configKey,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/application_creation_task', params=params)
        check_for_invalid_response(result)
        return result.json()

    def getDeployStatus(self,
                       application_id=None,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/application_creation_task', params=params)
        check_for_invalid_response(result)
        return result.json()

    def getAppStatus(self,
                    application_id=None,
                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/applications', params=params)
        check_for_invalid_response(result)
        return result.json()

    def applicationRemove(self,
                         application_id,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/applications', params=params)
        check_for_invalid_response(result)
        return result.json()

    def validateManifest(self,
                        manifest_data,
                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/application_creation_task', params=params)
        check_for_invalid_response(result)
        return result.json()

    def retrieveAPIs(self,
                    withParameters=None,
                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/restapi', params=params)
        check_for_invalid_response(result)
        return result.json()

    def retrieveApiParameters(self,
                             resourceId=None,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/restapi', params=params)
        check_for_invalid_response(result)
        return result.json()

    def getFieldsTitles(self,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/fieldsTitles', params=params)
        check_for_invalid_response(result)
        return result.json()

    def revokeOAuthClient(self,
                         client_id,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/revokeClient', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_analytic_user_feedback(self,
                                     feedback_id=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/delete_analytic_user_feedback', params=params)
        check_for_invalid_response(result)
        return result.json()

    def populateMembersForGroup(self,
                               dcName,
                               groupName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/populateMembersForGroup', params=params)
        check_for_invalid_response(result)
        return result.json()

    def retreiveUpdatedUsers(self,
                            dcName,
                            lastUpdateTime):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/retreiveUpdatedUsers', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_fam_crawler(self,
):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/disable_fam_crawler', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_fam_crawler(self,
                          activity_schedule_interval,
                          activity_schedule_units,
                          entitlement_schedule_interval,
                          entitlement_schedule_units,
                          extraction_start=None,
                          schedule_start=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/enable_fam_crawler', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_associated_stap_mu_groups(self,
                                      api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_associated_stap_mu_groups', params=params)
        check_for_invalid_response(result)
        return result.json()

    def restart_job_queue_listener(self,
):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/restart_job_queue_listener', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_entitlement_optimization(self,
                                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/disableEntitlementOptimization', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_entitlement_optimization(self,
                                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/enableEntitlementOptimization', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_entitlement_datasource_parameter(self,
                                            datasourceName,
                                            parameterName,
                                            parameterValue):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/setEntitlementDatasourceParameter', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_entitlement_optimization_info(self,
):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/getEntitlementOptimizationInfo', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_datasource_to_entitlement_optimization(self,
                                                  datasourceName,
                                                  isEnabled,
                                                  userScore=None,
                                                  objectScore=None,
                                                  extractActivity=None,
                                                  extractEntitlement=None,
                                                  generateRoleClusters=None,
                                                  generateNews=None,
                                                  generateRecommendations=None,
                                                  filterTempObjects=None,
                                                  filterIgnoreVerbs=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/addDatasourceToEntitlementOptimization', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_datasource_from_entitlement_optimization(self,
                                                       datasourceName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/removeDatasourceFromEntitlementOptimization', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_ranger_configs(self,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_ranger_configs', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_ranger_config(self,
                         clusterName,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/get_ranger_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_ranger_config(self,
                         hostname,
                         clusterName,
                         userName,
                         password,
                         port=None,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/add_ranger_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_ranger_staps(self,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_ranger_staps', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_ranger_services_status(self,
                                  clusterName,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/get_ranger_services_status', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_ranger_service(self,
                          clusterName,
                          serviceName,
                          stapHostName,
                          enableMonitoring,
                          port=None,
                          api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/add_ranger_service', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_monitoring_ranger_service(self,
                                        clusterName,
                                        serviceName,
                                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/enable_monitoring_ranger_service', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_monitoring_ranger_service(self,
                                         clusterName,
                                         serviceName,
                                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/disable_monitoring_ranger_service', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_ranger_service(self,
                             clusterName,
                             serviceName,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/remove_ranger_service', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_ranger_config(self,
                            clusterName,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/remove_ranger_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_ranger_service(self,
                             clusterName,
                             serviceName,
                             stapHostName,
                             port=None,
                             api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_ranger_service', params=params)
        check_for_invalid_response(result)
        return result.json()

    def update_ranger_config(self,
                            hostname,
                            clusterName,
                            userName,
                            password,
                            port=None,
                            newClusterName=None,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/update_ranger_config', params=params)
        check_for_invalid_response(result)
        return result.json()

    def run_database_instance_discovery(self,
                                       stapHost,
                                       replaceInspectionEngine=None,
                                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/run_database_instance_discovery', params=params)
        check_for_invalid_response(result)
        return result.json()

    def delete_inactive_stap(self,
                            stapHost,
                            force=None,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/delete_inactive_stap', params=params)
        check_for_invalid_response(result)
        return result.json()

    def refresh_stap_info(self,
                         stapHost,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/refresh_stap_info', params=params)
        check_for_invalid_response(result)
        return result.json()

    def run_diagnostics(self,
                       stapHost,
                       level=None,
                       durationInSec=None,
                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/run_diagnostics', params=params)
        check_for_invalid_response(result)
        return result.json()

    def change_tracker_get_params(self,
                                 task=None,
                                 paramName=None,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/change_tracker_get_params', params=params)
        check_for_invalid_response(result)
        return result.json()

    def change_tracker_set_params(self,
                                 paramName,
                                 paramValue,
                                 task,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/change_tracker_set_params', params=params)
        check_for_invalid_response(result)
        return result.json()

    def change_tracker_get_events(self,
                                 host=None,
                                 taskType=None,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/change_tracker_get_events', params=params)
        check_for_invalid_response(result)
        return result.json()

    def change_tracker_get_tasks(self,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/change_tracker_get_tasks', params=params)
        check_for_invalid_response(result)
        return result.json()

    def change_tracker_reset(self,
                            host,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/change_tracker_reset', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_native_audit_objects(self,
                                host,
                                service_name,
                                port,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/nau_objects_list', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_native_audit_collectors(self,
                                   host,
                                   service_name,
                                   port,
                                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/nau_collectors_list', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_native_audit_configurations(self,
                                       host,
                                       service_name,
                                       port,
                                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/nau_configurations', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_native_audit(self,
                           datasource_name,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/enable_native_audit', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_native_audit(self,
                            datasource_name,
                            api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/disable_native_audit', params=params)
        check_for_invalid_response(result)
        return result.json()

    def restart_cloud_instance(self,
                              datasource_name,
                              api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/restart_cloud_instance', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_objects_native_audit(self,
                                objects,
                                datasource_name,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/add_objects_native_audit', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_objects_native_audit(self,
                                   objects,
                                   datasource_name,
                                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/remove_objects_native_audit', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_ip_to_sg(self,
                    datasource_name,
                    api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/add_ip_to_sg', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_parameter_names_by_report_name(self,
                                           reportName):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_parameter_names_by_report_name', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_ip_to_alias_selected(self,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/ip_to_alias_selected', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_ip_to_alias_selected(self,
                                ipToAliasSelected,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/ip_to_alias_selected', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_ip_to_alias_overwrites(self,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/ip_to_alias_overwrites', params=params)
        check_for_invalid_response(result)
        return result.json()

    def set_ip_to_alias_overwrites(self,
                                  ipToAliasOverwrites,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/ip_to_alias_overwrites', params=params)
        check_for_invalid_response(result)
        return result.json()

    def list_health_node(self,
                        api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/list_health_node', params=params)
        check_for_invalid_response(result)
        return result.json()

    def enable_big_data_interface(self,
                                 profile_name,
                                 unit_group=None,
                                 ds_host=None,
                                 ds_port=None,
                                 ds_user=None,
                                 ds_password=None,
                                 ds_desc=None,
                                 target_host=None,
                                 target_port=None,
                                 target_user=None,
                                 target_password=None,
                                 target_path=None,
                                 start_date=None,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/bigDataInterface', params=params)
        check_for_invalid_response(result)
        return result.json()

    def local_enable_big_data_interface(self,
                                       profile_name,
                                       start_date=None,
                                       api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/bigDataInterface', params=params)
        check_for_invalid_response(result)
        return result.json()

    def add_dm_to_profile(self,
                         profile_name,
                         datamart_name,
                         unit_type=None,
                         cron_string=None,
                         category=None,
                         api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/datamartInProfile', params=params)
        check_for_invalid_response(result)
        return result.json()

    def clone_extraction_profile(self,
                                profile_name,
                                clone_profile_name,
                                api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_put('/restAPI/extractionProfile', params=params)
        check_for_invalid_response(result)
        return result.json()

    def get_extraction_profile_info(self,
                                   profile_name=None,
                                   verbose=None,
                                   api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_get('/restAPI/extractionProfile', params=params)
        check_for_invalid_response(result)
        return result.json()

    def unschedule_datamart(self,
                           datamart_name,
                           api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/datamartSchedule', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_dm_from_profile(self,
                              profile_name,
                              datamart_name,
                              api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/datamartInProfile', params=params)
        check_for_invalid_response(result)
        return result.json()

    def remove_extraction_profile(self,
                                 profile_name,
                                 api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/extractionProfile', params=params)
        check_for_invalid_response(result)
        return result.json()

    def disable_big_data_interface(self,
                                  disable_readback=None,
                                  api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_delete('/restAPI/bigDataInterface', params=params)
        check_for_invalid_response(result)
        return result.json()

    def replace_active_profile(self,
                              new_active_profile,
                              api_target_host=None):
        arguments = {k: v for k, v in locals().iteritems() if k != 'self'}
        params = {}
        for k, v in arguments.iteritems():
            if v is not None:
                params[k] = v
        result = self.grd_connection.grd_post('/restAPI/extractionProfile', params=params)
        check_for_invalid_response(result)
        return result.json()
    
    def create_online_report(self, reportName, query_from_date, query_to_date, show_aliases='TRUE', db_user_name='%',
                                 remote_source='', host_name_like='%', indexFrom=1, fetchSize='', sortColumn='',
                                 sortType='', additionalParamDictionary=None):
            """
                        create_online_report returns a report in json style.
            parameters:
            reportName - the name of the required report
            query_from_date - from what date to start query, e.g. : NOW -10 DAY
            query_to_date - until what day to start query, e.g. : NOW
    
    
            The rest of the parameters are optional:
    
            show_aliases - boolean
            db_user_name
            remote_source
            host_name_like
            indexFrom - an integer of the serial number of the first record to be returned
            fetchSize - an integer of the number of records returned
            sortColumn
            sortType
            additionalParamDictionary - an optional dictionary containing key value pairs, where each key is an additional
                                       parameter, and the corresponding value is the value assigned to that parameter.
            """
            if indexFrom < 1:
                raise IndexError("parameter indexFrom must be at least 1")
    
            report_parameters = {"QUERY_FROM_DATE": query_from_date,
                                 "QUERY_TO_DATE": query_to_date,
                                 "SHOW_ALIASES": show_aliases,
                                 "DBUserName": db_user_name,
                                 "REMOTE_SOURCE": remote_source,
                                 "HostnameLike": host_name_like,
                                 "hostLike": host_name_like}
    
            if additionalParamDictionary is not None:
                report_parameters.update(additionalParamDictionary)
    
            task = {"reportName": reportName, "indexFrom": indexFrom, "reportParameter": report_parameters,
                    "fetchSize": fetchSize,
                    "sortColumn": sortColumn, "sortType": sortType}
    
            response = self.grd_connection.grd_post('/restAPI/online_report', params=task)
            check_for_invalid_response(response)
    
            return response.json()
    
    def create_online_report_generator(self, reportName, query_from_date, query_to_date, show_aliases='TRUE',
                                           db_user_name='%', remote_source='', host_name_like='%',
                                           fetchSize = 20, sortColumn = '', sortType = '', additionalParamDictionary=None):
    
            report_parameters = {"QUERY_FROM_DATE": query_from_date,
                                 "QUERY_TO_DATE": query_to_date,
                                 "SHOW_ALIASES": show_aliases,
                                 "DBUserName": db_user_name,
                                 "REMOTE_SOURCE": remote_source,
                                 "HostnameLike": host_name_like,
                                 "hostLike": host_name_like}
    
            if additionalParamDictionary is not None:
                report_parameters.update(additionalParamDictionary)
    
            indexFrom = 1
            while True:
                task = {"reportName": reportName, "indexFrom": indexFrom, "reportParameter": report_parameters,
                        "fetchSize": fetchSize, "sortColumn": sortColumn, "sortType": sortType}
                response = self.grd_connection.grd_post('/restAPI/online_report', params=task)
                check_for_invalid_response(response)
                indexFrom += fetchSize
                yield response.json()
    
    def search(self,
                   QUERY=None,
                   COUNT=None,
                   START=None,
                   WITH_FACETS=None,
                   CATEGORY=None,
                   SUMMARY_BY=None,
                   START_TIME=None,
                   END_TIME=None,
                   api_target_host=None):
    
            titles_dict = json.loads(self.getFieldsTitles()['Message'])
    
            task = {"QUERY": QUERY, "COUNT": COUNT, "START": START, "WITH_FACETS": WITH_FACETS,
                    "CATEGORY": CATEGORY, "SUMMARY_BY": SUMMARY_BY, "START_TIME": START_TIME,
                    "END_TIME": END_TIME, "api_target_host": api_target_host}
    
            response = self.grd_connection.grd_get('/restAPI/search', params=task)
            check_for_invalid_response(response)
            response = response.json()[0]
            if "maxLengthMapByOrder" in response:
                order_of_fields = [x.keys()[0] for x in response["maxLengthMapByOrder"]]
                response.pop("maxLengthMapByOrder")
            else:
                order_of_fields = []
            for record in response["items"]:
                new_record = OrderedDict()
                new_record['id'] = record['id']
                for field_number in order_of_fields:
                    if field_number in record:
                        new_record[titles_dict[field_number]] = record[field_number]
                response["items"][response["items"].index(record)] = new_record
            return [response]
    
    def import_definitions(self,
                           file,
                           api_target_host=None):               
            result = self.grd_connection.grd_post('/restAPI/import_definitions', params=None, multipart_data={'file': file} )
            check_for_invalid_response(result)
            return result.json()
