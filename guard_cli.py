from paramiko import SSHClient, AutoAddPolicy, SSHException
from paramiko_expect import SSHClientInteraction
from re import sub, findall, search
from time import sleep
from urllib import urlopen
from demjson import decode
# from app.gpylib import gpylib


# logger = gpylib.log

def logger(s):
    print(s)


class GuardCLI(SSHClient):
    """
    A class that represents an SSH Paramiko connection to the Guardium CLI.
    Class object type is 'SSHClient' (from Paramiko).
    """
    def __init__(self, host, port, username, password, timeout=None, missing_host_key_policy=True, sock=None):
        """

        Args:
            host: IP or hostname of the host that is being connected to via SSH.
            port: SSH port number (SSH default is 22).
            username:
            password:
            timeout(int; seconds): SSH connection timeout.  Default is 30 seconds.
            missing_host_key_policy:
            sock (channel paramiko): paramiko socket
        """

        super(self.__class__, self).__init__()  # Note Python 3 syntax is super().__init__()

        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.sock = sock
        self.prompt = '.*> $'

        if missing_host_key_policy:
            self.set_missing_host_key_policy(AutoAddPolicy())

        try:
            self.connect(self.host,
                         port=self.port,
                         username=self.username,
                         password=self.password,
                         timeout=self.timeout,
                         sock=self.sock)

        except SSHException as e:
            logger('Cannot open an SSH session with the Guardium instance.')
            logger(str(e))
            raise Exception(str(e))

        self.interact = SSHClientInteraction(self, display=False,newline='\n')
        self.interact.expect('.*$')
        self.interact.send('')
        self.interact.expect(self.prompt)
        logger(self.interact.current_output_clean)

    def exec_cmd(self, command, print_stdout=True):
        """
        Executes a command within a paramiko SSH connection.

        Args:
            command(str):
            print_stdout(True/False):

        Returns: stdout

        """

        logger(self.username + "@" + self.host + "]# {}".format(command))  # log the command

        self.interact.send(command)
        self.interact.expect(self.prompt)
        stdout = self.interact.current_output_clean

        if print_stdout:   # log the output
            logger(stdout)
            print(stdout)

        return stdout

    def open_direct_tcpip_channel(self, dest_ssh_host, dest_ssh_port, local_ssh_host, local_ssh_port):
        """
        Opens a channel based on an existing SSH connection so that 'nested' SSH connections can be made

        Args:
            dest_ssh_host(str): hostname/IP of remote ssh server
            dest_ssh_port(int): port of remote ssh server
            local_ssh_host (str): hostname/IP of local ssh connection; 127.0.0.1
            local_ssh_port(int): port of local ssh connection

        Returns: channel

        """
        __dest_ssh = (dest_ssh_host, dest_ssh_port)  # (tuple): hostname/IP, port of remote ssh server
        __local_ssh = (local_ssh_host, local_ssh_port)  # local_ssh (tuple): hostname/IP, port of local ssh connection

        transport = self.get_transport()
        channel = transport.open_channel("direct-tcpip", __dest_ssh, __local_ssh)

        return channel

    def get_available_patches_for_install(self, installed_patches_list=None):
        if not installed_patches_list:
            installed_patches_list = self.get_installed_patches()

        result = self.exec_cmd('show system patch available', print_stdout=False)

        # Parse the results
        results_list = []
        if 'No patch available' in result:
            return results_list

        header_str = None
        for line in result.splitlines():
            if 'Attempting to retrieve the patch information' in line:
                pass

            elif line == '':
                pass

            elif 'P#' in line:
                header_str = line
                num_col_start = header_str.index('P#')
                des_col_start = header_str.index('Description')
                ver_col_start = header_str.index('Version')
                md5_col_start = header_str.index('Md5sum')
                dep_col_start = header_str.index('Dependencies')

            elif line == 'ok':
                pass

            else:
                if header_str is None:  # Can't parse the data without header
                    return results_list

                patch_number = line[0:des_col_start].strip()

                # Remove any installed or schedule patches that are 'available'

                if not (any(d.get('number', None) == patch_number for d in installed_patches_list)) \
                        or patch_number == '9997':

                    patch_description = line[des_col_start:ver_col_start].strip()
                    patch_version = line[ver_col_start:md5_col_start].strip()
                    patch_md5sum = line[md5_col_start:dep_col_start].strip()
                    patch_dependencies = line[dep_col_start:len(line)].strip()

                    results_list.append({'number': patch_number, 'description': patch_description, 'version': patch_version,
                                         'md5sum': patch_md5sum, 'dependencies': patch_dependencies})

        return results_list

    def get_installed_patches(self):
        result = self.exec_cmd('show system patch installed', print_stdout=False)

        results_list = []

        try:
            if 'USAGE:' in result:
                logger('Unable to get list of installed patches because an installation is underway.')
                return results_list
                # USAGE:  show system patch <arg>, where arg is:
                # When a patch is installing, this feature becomes unavailable

            # Parse the results
            header_str = None
            for line in result.splitlines():
                if 'Attempting to retrieve the patch information' in line:
                    pass

                elif line == '':
                    pass

                elif 'P#' in line:
                    header_str = line
                    who_col_start = header_str.index('Who')
                    des_col_start = header_str.index('Description')
                    req_col_start = header_str.index('Request Time')
                    sta_col_start = header_str.index('Status')

                elif line == 'ok':
                    pass

                else:
                    if header_str is None:
                        # Can't parse the results without the table header
                        return results_list

                    # Patch table parsed based on the character-width of the column headers
                    patch_number = line[0:who_col_start].strip()
                    patch_who_installed = line[who_col_start:des_col_start].strip()
                    patch_description = line[des_col_start:req_col_start].strip()
                    patch_submit_time = line[req_col_start:sta_col_start].strip()
                    patch_install_status = line[sta_col_start:len(line)].strip()

                    results_list.append({'number': patch_number,
                                         'who': patch_who_installed,
                                         'description': patch_description,
                                         'install_start_time': patch_submit_time,
                                         'status': patch_install_status})

            return results_list

        except IndexError as e:
            logger(str(e))
            return results_list

    def start_file_server(self, source_ip_address, timeout=3600):
        """
        This command limits access to just the machine being called or to the supplied IP address
        Where duration is time in seconds, range 60 (minimum) to 3600 (maximum)
        """
        self.interact.send('fileserver {ip} {timeout}'.format(ip=source_ip_address, timeout=timeout))
        self.interact.expect('.*')
        result = self.interact.current_output_clean

        timeout_counter = 0
        # Wait for the result of the command
        while 'is' not in result:
            sleep(1)
            self.interact.expect('.*')
            result = self.interact.current_output_clean
            timeout_counter += 1

            if timeout_counter > 30:
                logger('A timeout occurred while waiting for the fileserver to start.')
                raise Exception('A timeout occurred while waiting for the fileserver to start.')

        if 'The file server is ready' in result:
            logger(result)
            fileserver_link = findall(r'https.*', result)
            if fileserver_link:
                logger(fileserver_link[0])
                return True
            else:
                return True

        elif 'already running' in result:
            logger('Fileserver is already running.')

            return True

        else:
            logger('A problem occurred while trying to start the fileserver.')
            logger(result)
            raise Exception('A problem occurred while trying to start the fileserver.')

    def stop_file_server(self):
        """
        Assumes the fileserver is already running.  "Press ENTER to stop the file server."
        """
        self.interact.send('\r\n')
        self.interact.expect(self.prompt, timeout=5)
        logger(self.interact.current_output_clean)
        return True

    def get_all_available_updates_json(self):
        url = 'https://ibm.biz/GuardiumUpdateCheck'
        patch_list_raw = urlopen(url).read()

        patch_list_raw = sub(r'\s\//.*', ' ', patch_list_raw)  # Removes majority of comments
        patch_list_raw = sub(r'\//end of version.*', ' ', patch_list_raw)  # Removes comment at the end
        patch_list_raw = patch_list_raw.replace('var PATCH_INFO = \n', '')  # Get rid of the var statement
        patch_list_raw = ' '.join(patch_list_raw.split())  # Remove white space
        patch_list_d = decode(patch_list_raw)  # Convert from javascript to python

        return patch_list_d

    def get_release_version(self):
        # show build
        build_info = self.exec_cmd('show build', print_stdout=False)

        version_line = ''
        # isolate the build version line
        for line in build_info.splitlines():
            if 'Build:' in line:
                version_line = line

        release_version = sub(r'Build\:\s', '', version_line)  # Isolate the major version

        return release_version

    def get_highest_gpu_level_installed(self, installed_patches_list):
        highest_gpu_installed = 0
        for patch in installed_patches_list:
            patch_number = int(patch['number'])
            if 'Guardium Patch Update (GPU)' in patch['description']:
                if patch_number > highest_gpu_installed:
                    highest_gpu_installed = patch_number

        return str(highest_gpu_installed)

    def check_for_available_updates(self, installed_gpu_level=None, installed_release_version=None,
                                    all_updates_list=None, installed_patches=None):

        if not installed_patches:
            installed_patches = self.get_installed_patches()

        installed_patch_numbers_list = []
        for patch in installed_patches:
            installed_patch_numbers_list.append(patch['number'])

        if not installed_release_version:
            installed_release_version = self.get_release_version
        if not installed_gpu_level:
            installed_gpu_level = self.get_highest_gpu_level_installed(installed_patches)

        if not all_updates_list:
            all_updates_list = self.get_all_available_updates_json()

        # build a list of applicable patches
        missing_patches_list = []
        for patch_version in all_updates_list:
            if patch_version['patchVersion'] == installed_release_version:
                # Release Version matches.  Now go through the components (Appliance Patch, DPS)
                for component in patch_version['components']:
                    for gpu in component['gpus']: #
                        if gpu['minGpuLevel'] == 'all' or gpu['minGpuLevel'] == installed_gpu_level:
                            for patch in gpu['patches']:
                                if patch['type'] == 'DPS':  # DPS patches don't have patch numbers
                                    match = False
                                    for installed_patch in installed_patches:
                                        if installed_patch['description'] in patch['description']:
                                            match = True

                                    if match is False:  # DPS patch is missing
                                        missing_patches_list.append(patch)

                                else:
                                    if patch['number'] not in installed_patch_numbers_list:  # Patch is not installed
                                            # Patch already included in a release that is installed?
                                        if installed_gpu_level not in patch['includedInPatches']:
                                            missing_patches_list.append(patch)

        return missing_patches_list

    def build_file_server_link(self):
        host_ip = ''
        result = self.exec_cmd('show network interface all', print_stdout=False)
        try:
            host_ip = search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', result).group()
        except Exception as e:
            logger(e)
            logger('Unable to determine IP Address of Guardium instance.')

        return host_ip, 'https://' + host_ip + ':8445'

    def check_if_still_installing(self, patch_number, installed_patches_list=None):
        if not installed_patches_list:
            installed_patches_list = self.get_installed_patches()

        for patch in installed_patches_list:
            if patch['number'] == patch_number:
                if 'DONE' in patch['status']:
                    return False
                else:
                    return True  # Still installing...

        return False  # Install has finished because the patch number is no longer in the list of available for install

    def install_patch(self, patch_number):

        # store system patch install sys

        # List the files in the patches directory:

        # 1. SqlGuard-10.0p600_GPU_Oct_2018_V10.6.tgz.enc.sig
        # 2. SqlGuard-10.0p9997.tgz.enc.sig
        #
        # Please choose patches to install (1-2, or multiple numbers separated by ",", or q to quit):

        self.interact.send('store system patch install sys')
        logger('store system patch install sys')

        self.interact.expect('.*')
        result = self.interact.current_output_clean

        # List the files in the patches directory:

        # 1. SqlGuard-10.0p600_GPU_Oct_2018_V10.6.tgz.enc.sig
        # 2. SqlGuard-10.0p9997.tgz.enc.sig

        if 'No files in the patches directory to install' in result:
            logger(str(result))
            self.interact.send('\n')
            self.interact.expect('.*')
            logger('There are no available patches to install.')
            return 'There are no available patches to install.'

        choice_number = self.get_install_choice_number(result, patch_number)
        logger('Choice number for patch ' + patch_number + ' is ' + choice_number)

        self.interact.send('\n')
        self.interact.expect('.*')
        result = self.interact.current_output_clean
        # Please choose patches to install
        if not 'Please choose patches to install' in result:
            logger(result)
            return 'CLI not what expected.  Unable to install patch at this time.  Please retry.'

        logger('Submitting patch...')
        self.interact.send(choice_number)

        self.interact.expect('.*', timeout=60)  # Big patches can take a long time to submit
        logger(self.interact.current_output_clean)  # Install item 3 (or whatever the choice was)
        # Blank line u''
        self.interact.expect('.*', timeout=120)  # This is where the result comes;  big patches take a long time
        result = self.interact.current_output_clean

        if 'already installed successfully' in result:
            logger(str(result))
            return result

        if 'Patch has been submitted' in result:
            logger(str(result))
            return True  # Patch is being installed...

            # Install item 1
            # Patch has been submitted, and will be installed according to the request time,
            # please check installed patches report or CLI (show system patch installed).
            #
            # Please don't forget to remove your media if necessary.
            # ok

        return True  # For large patches, it can hang a long time waiting for processing, so just expect it's True

    def get_install_choice_number(self, result, patch_number):

        if 'List the files in the patches directory' not in result:
            logger(result)
            raise Exception('Unexpected problem occurred when trying to install patch #' + \
                   str(patch_number) + '. Please try again.')

        # Parse the results to figure out the correct option
        # Isolate to list list of patches

        for line in result.splitlines():
            if 'List the files in the patches directory' in line:
                pass

            elif 'Please choose patches' in line:
                pass

            elif line == '':
                pass

            else:
                columns = [s.strip() for s in line.split('. ') if s]

                choice_num = columns[0]
                patch_description = columns[1]

                if patch_number in patch_description:

                    return choice_num

        logger('Unable to locate an install choice for patch #' + patch_number)
        raise Exception('Unexpected problem occurred when trying to install patch #' + \
                        str(patch_number) + '. Please try again.')

    def grdapi_install_patch(self, patch_number, scheduled_date=""):

        if scheduled_date:  # patch_date is optional
            result = self.exec_cmd(
                'grdapi patch_install patch_number={} patch_date="{}"'.format(patch_number, scheduled_date),
                print_stdout=False)

        else:
            result = self.exec_cmd('grdapi patch_install patch_number={}'.format(patch_number), print_stdout=False)

        if 'User has insufficient privileges' in result:
            logger(str(result))
            raise Exception('Failed to install patch "' + patch_number + '"; appliance is missing license.')

        if 'ERR' in result:
            logger(str(result))
            raise Exception('Failed to install patch "' + patch_number + '\n' + str(result))

        # ID=0
        # ok
        return True

    def get_scheduled_patches(self, installed_patches_list=None):
        if installed_patches_list is None:
            installed_patches_list = self.get_installed_patches()

        scheduled_patches_list = []
        for patch in installed_patches_list:
            if patch['status'] == 'Requested':
                scheduled_patches_list.append(patch)

        return scheduled_patches_list

    def delete_scheduled_patch(self, patch_number):
        # self.exec_cmd('delete scheduled-patch')
        self.interact.send('delete scheduled-patch')
        logger('delete scheduled-patch')
        self.interact.expect('.*', timeout=30)

        logger('--------Patches that can be deleted list:------')
        logger(self.interact.current_output_clean)
        logger('-----------------------------------------------')

        self.interact.send(patch_number)
        self.interact.expect('.*', timeout=30)

        result = self.interact.current_output_clean  # Remove the patch number 510 to install
        logger('-------------Remove patch result---------------')
        logger(result)
        logger('-----------------------------------------------')

        if 'Invalid patch number' in result:

            # Exception occured.  Quit.
            self.interact.send('q')
            self.interact.expect('.*')
            logger(self.interact.current_output_clean)

            self.interact.send('\n')
            self.interact.expect('.*')
            logger(self.interact.current_output_clean)

            raise Exception('Patch #' + patch_number + ' cannot be deleted as requested.  Quitting...')

        logger('Completed delete of scheduled patch: ' + patch_number)
        self.interact.send('\n')
        self.interact.expect('.*', timeout=10)
        logger(self.interact.current_output_clean)

        return True



    def get_appliance_type(self):
        result = self.exec_cmd('show unit type', print_stdout=False)  # u'Standalone Aggregator  \nok\n'
        return result.splitlines()[0].strip()
