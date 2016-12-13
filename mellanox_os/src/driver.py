import json
import time
import paramiko
import re
from cloudshell.api.cloudshell_api import CloudShellAPISession

from cloudshell.networking.apply_connectivity.apply_connectivity_operation import apply_connectivity_changes
from cloudshell.networking.apply_connectivity.models.connectivity_result import ConnectivitySuccessResponse
from cloudshell.shell.core.interfaces.save_restore import OrchestrationSaveResult, OrchestrationSavedArtifact, \
    OrchestrationSavedArtifactInfo, OrchestrationRestoreRules
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, ResourceCommandContext, AutoLoadResource, \
    AutoLoadAttribute, AutoLoadDetails, CancellationContext

from cloudshell.core.logger.qs_logger import get_qs_logger, log_execution_info


class MellanoxOsDriver (ResourceDriverInterface):
    def _log(self, context, message):
        # with open(r'c:\programdata\qualisystems\gigamon.log', 'a') as f:
        #     f.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + ' GigamonDriver _log called\r\n')
        try:
            try:
                resid = context.reservation.reservation_id
            except:
                resid = 'out-of-reservation'
            try:
                resourcename = context.resource.fullname
            except:
                resourcename = 'no-resource'
            logger = get_qs_logger(resid, 'Mellanox-OS-L2', resourcename)
            logger.info(message)
        except Exception as e:
            try:
                with open(r'c:\programdata\qualisystems\mellanox-os.log', 'a') as f:
                    f.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + ' qs_logger failed: ' + str(e)+'\r\n')
                    f.write(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + ' (QS LOGGER NOT WORKING): ' + message+'\r\n')
            except:
                pass

    def _ssh_disconnect(self, context, ssh, channel):
        self._log(context, 'disconnnect')
        if self.fakedata:
            return
        ssh.close()

    def _ssh_connect(self, context, host, port, username, password, prompt_regex):
        self._log(context, 'connect %s %d %s %s %s' % (host, port, username, password, prompt_regex))
        if self.fakedata:
            return
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        tries = 0
        while True:
            try:
                tries += 1
                ssh.connect(host,
                            port=port,
                            username=username,
                            password=password,
                            look_for_keys=True)
                channel = ssh.invoke_shell(term='console', width=300, height=100000)
                return ssh, channel, self._ssh_read(context, ssh, channel, prompt_regex)  # eat banner
            except Exception as e:
                if tries >= 4:
                    self._log(context, 'Connection failed after 4 tries')
                    raise e
                self._log(context, 'Password rejected or other connectivity error: %s\nsleeping 10 seconds and retrying...' % str(e))
                time.sleep(10)

    def _ssh_write(self, context, ssh, channel, command):
        self._log(context, 'sending: <<<' + command + '>>>')
        if self.fakedata:
            print command
            return
        channel.send(command)
        self._log(context, 'send complete')

    def _ssh_read(self, context, ssh, channel, prompt_regex):
        if self.fakedata:
            return
        rv = ''
        self._log(context, 'read...')
        while True:
            # self.channel.settimeout(30)
            self._log(context, 'recv')
            r = channel.recv(2048)
            self._log(context, 'recv returned: <<<' + str(r) + '>>>')
            if r:
                rv += r
            if rv:
                t = rv
                t = re.sub(r'(\x9b|\x1b)[[?;0-9]*[a-zA-Z]', '', t)
                t = re.sub(r'(\x9b|\x1b)[>=]', '', t)
                t = re.sub('.\b', '', t) # not r''
            else:
                t = ''
            if not r or len(re.findall(prompt_regex, t)) > 0:
                rv = t
                if rv:
                    rv = rv.replace('\r', '\n')
                self._log(context, '\n\nread complete: <<<' + str(rv) + '>>>\n\n')
                return rv

    def _ssh_command(self, context, ssh, channel, command, prompt_regex):
        if self.fakedata:
            print command
            if command in self.fakedata:
                print self.fakedata[command]
                return self.fakedata[command]
            else:
                return ''
        else:
            self._ssh_write(context, ssh, channel, command + '\n')
            rv = self._ssh_read(context, ssh, channel, prompt_regex)
            if '\n%' in rv.replace('\r', '\n'):
                es = 'CLI error message: ' + rv
                self._log(context, es)
                raise Exception(es)
            return rv

    def _connect(self, context):
        if self.fakedata:
            return None, None, None
        try:
            domain = context.reservation.domain
        except:
            domain = 'Global'

        api = CloudShellAPISession(context.connectivity.server_address,
                                   token_id=context.connectivity.admin_auth_token,
                                   port=context.connectivity.cloudshell_api_port,
                                   domain=domain)
        address = context.resource.address
        user = context.resource.attributes['User']
        password = api.DecryptPassword(context.resource.attributes['Password']).Value

        ssh, channel, o = self._ssh_connect(context, address, 22, user, password, ' > ')

        # self._ssh_command(context, ssh, channel, 'terminal type console', ' > ')
        # self._ssh_command(context, ssh, channel, 'terminal length 999', ' > ')
        e = self._ssh_command(context, ssh, channel, 'enable', '#|ssword:')
        if 'ssword:' in e:
            self._ssh_command(context, ssh, channel, api.DecryptPassword(context.resource.attributes['Enable Password']).Value, '[^[#]# ')
        # self._ssh_command(context, ssh, channel, 'cli session terminal type dumb', '[^[#]# ')
        return ssh, channel, o

    def _disconnect(self, context, ssh, channel):
        if self.fakedata:
            return
        self._ssh_disconnect(context, ssh, channel)


    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        self.fakedata = None

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        pass

    # <editor-fold desc="Networking Standard Commands">
    def restore(self, context, cancellation_context, path, configuration_type, restore_method, vrf_management_name):
        """
        Restores a configuration file
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str path: The path to the configuration file, including the configuration file name.
        :param str restore_method: Determines whether the restore should append or override the current configuration.
        :param str configuration_type: Specify whether the file should update the startup or running config.
        :param str vrf_management_name: Optional. Virtual routing and Forwarding management name
        """
        pass

    def save(self, context, cancellation_context, folder_path, configuration_type, vrf_management_name):
        """
        Creates a configuration file and saves it to the provided destination
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str configuration_type: Specify whether the file should update the startup or running config. Value can one
        :param str folder_path: The path to the folder in which the configuration file will be saved.
        :param str vrf_management_name: Optional. Virtual routing and Forwarding management name
        :return The configuration file name.
        :rtype: str
        """
        pass

    def load_firmware(self, context, cancellation_context, path, vrf_management_name):
        """
        Upload and updates firmware on the resource
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param str path: path to tftp server where firmware file is stored
        :param str vrf_management_name: Optional. Virtual routing and Forwarding management name
        """
        pass

    def run_custom_command(self, context, cancellation_context, custom_command):
        """
        Executes a custom command on the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str custom_command: The command to run. Note that commands that require a response are not supported.
        :return: the command result text
        :rtype: str
        """
        pass

    def run_custom_config_command(self, context, cancellation_context, custom_command):
        """
        Executes a custom command on the device in configuration mode
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str custom_command: The command to run. Note that commands that require a response are not supported.
        :return: the command result text
        :rtype: str
        """
        pass

    def shutdown(self, context, cancellation_context):
        """
        Sends a graceful shutdown to the device
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        """
        pass

    # </editor-fold>

    # <editor-fold desc="Orchestration Save and Restore Standard">
    def orchestration_save(self, context, cancellation_context, mode, custom_params):
        """
        Saves the Shell state and returns a description of the saved artifacts and information
        This command is intended for API use only by sandbox orchestration scripts to implement
        a save and restore workflow
        :param ResourceCommandContext context: the context object containing resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str mode: Snapshot save mode, can be one of two values 'shallow' (default) or 'deep'
        :param str custom_params: Set of custom parameters for the save operation
        :return: SavedResults serialized as JSON
        :rtype: OrchestrationSaveResult
        """

        # See below an example implementation, here we use jsonpickle for serialization,
        # to use this sample, you'll need to add jsonpickle to your requirements.txt file
        # The JSON schema is defined at: https://github.com/QualiSystems/sandbox_orchestration_standard/blob/master/save%20%26%20restore/saved_artifact_info.schema.json
        # You can find more information and examples examples in the spec document at https://github.com/QualiSystems/sandbox_orchestration_standard/blob/master/save%20%26%20restore/save%20%26%20restore%20standard.md
        '''
        # By convention, all dates should be UTC
        created_date = datetime.datetime.utcnow()

        # This can be any unique identifier which can later be used to retrieve the artifact
        # such as filepath etc.

        # By convention, all dates should be UTC
        created_date = datetime.datetime.utcnow()

        # This can be any unique identifier which can later be used to retrieve the artifact
        # such as filepath etc.
        identifier = created_date.strftime('%y_%m_%d %H_%M_%S_%f')

        orchestration_saved_artifact = OrchestrationSavedArtifact('REPLACE_WITH_ARTIFACT_TYPE', identifier)

        saved_artifacts_info = OrchestrationSavedArtifactInfo(
            resource_name="some_resource",
            created_date=created_date,
            restore_rules=OrchestrationRestoreRules(requires_same_resource=True),
            saved_artifact=orchestration_saved_artifact)

        return OrchestrationSaveResult(saved_artifacts_info)
        '''
        pass

    def orchestration_restore(self, context, cancellation_context, saved_artifact_info, custom_params):
        """
        Restores a saved artifact previously saved by this Shell driver using the orchestration_save function
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param CancellationContext cancellation_context: Object to signal a request for cancellation. Must be enabled in drivermetadata.xml as well
        :param str saved_artifact_info: A JSON string representing the state to restore including saved artifacts and info
        :param str custom_params: Set of custom parameters for the restore operation
        :return: None
        """
        '''
        # The saved_details JSON will be defined according to the JSON Schema and is the same object returned via the
        # orchestration save function.
        # Example input:
        # {
        #     "saved_artifact": {
        #      "artifact_type": "REPLACE_WITH_ARTIFACT_TYPE",
        #      "identifier": "16_08_09 11_21_35_657000"
        #     },
        #     "resource_name": "some_resource",
        #     "restore_rules": {
        #      "requires_same_resource": true
        #     },
        #     "created_date": "2016-08-09T11:21:35.657000"
        #    }

        # The example code below just parses and prints the saved artifact identifier
        saved_details_object = json.loads(saved_details)
        return saved_details_object[u'saved_artifact'][u'identifier']
        '''
        pass

    # </editor-fold>

    # <editor-fold desc="Connectivity Provider Interface (Optional)">

    # The ApplyConnectivityChanges function is intended to be used for using switches as connectivity providers
    # for other devices. If the Switch shell is intended to be used a DUT only there is no need to implement it

    def ApplyConnectivityChanges(self, context, request):
        """
        Configures VLANs on multiple ports or port-channels
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param str request: A JSON object with the list of requested connectivity changes
        :return: a json object with the list of connectivity changes which were carried out by the switch
        :rtype: str
        """

        vlan2endpoints = {}
        for action in json.loads(request)['driverRequest']['actions']:
            vlan = str(action['connectionParams']['vlanId'])
            addr = '/'.join(action['actionTarget']['fullAddress'].split('/')[1:])
            if vlan not in vlan2endpoints:
                vlan2endpoints[vlan] = []
            if action['type'] in ['setVlan', 'removeVlan']:
                if vlan in vlan2endpoints and vlan2endpoints[vlan] and vlan2endpoints[vlan][0]['action'] != action['type']:
                    raise Exception('Conflicting action types %s, %s for vlan %s' % (action['type'], vlan2endpoints[vlan]['action'], vlan))
                vlan2endpoints[vlan].append({
                    'action': action['type'],
                    'addr': addr,  # '/'.join(addr.split('/')[1:]),
                    'actionId': action['actionId'],
                    'fullname': action['actionTarget']['fullName']
                })
        ssh, channel, _ = self._connect(context)
        try:
            self._ssh_command(context, ssh, channel, 'configure terminal', ' # ')
            try:
                for vlan in vlan2endpoints:
                    isset = vlan2endpoints[vlan][0]['action'] == 'setVlan'
                    for endpoint in vlan2endpoints[vlan]:
                        addr = endpoint['addr']
                        if isset:
                            self._ssh_command(context, ssh, channel, 'vlan %s' % vlan, '[^[#]# ')
                            self._ssh_command(context, ssh, channel, 'exit', '[^[#]# ')
                            self._ssh_command(context, ssh, channel, 'interface ethernet %s switchport mode access' % addr, '[^[#]# ')
                            self._ssh_command(context, ssh, channel, 'interface ethernet %s switchport access vlan %s' % (addr, vlan), '[^[#]# ')
                        else:
                            self._ssh_command(context, ssh, channel, 'interface ethernet %s switchport access vlan 1' % (addr), '[^[#]# ')
                            # self._ssh_command(context, ssh, channel, 'no interface ethernet %s switchport access vlan' % addr, '[^[#]# ')
                    if not isset:
                        self._ssh_command(context, ssh, channel, 'no vlan %s' % vlan, '[^[#]# ')
            finally:
                self._ssh_command(context, ssh, channel, 'exit', ' # ')
        finally:
            self._disconnect(context, ssh, channel)

        # rv = {
        #     'driverResponse': {
        #         'actionResults': []
        #     }
        # }
        # for vlan in vlan2endpoints:
        #     for endpoint in vlan2endpoints[vlan]:
        #         rv['driverResponse']['actionResults'].append({
        #             'actionId': endpoint['actionId'],
        #             'errorMessage': '',
        #             'infoMessage': 'Success',
        #             'success': 'True',
        #             'type': endpoint['action'],
        #             'updatedInterface': endpoint['fullname']
        #         })
        #
        # s = json.dumps(rv)
        #
        # self._log(context, 'Returning: ' + s)
        #
        # return s
        return apply_connectivity_changes(request=request,
                                          add_vlan_action=lambda x: ConnectivitySuccessResponse(x,'Success'),
                                          remove_vlan_action=lambda x: ConnectivitySuccessResponse(x,'Success'))




    # </editor-fold>

    # <editor-fold desc="Discovery">

    def get_inventory(self, context):
        """
        Discovers the resource structure and attributes.
        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """
        # See below some example code demonstrating how to return the resource structure
        # and attributes. In real life, of course, if the actual values are not static,
        # this code would be preceded by some SNMP/other calls to get the actual resource information
        '''
           # Add sub resources details
           sub_resources = [ AutoLoadResource(model ='Generic Chassis',name= 'Chassis 1', relative_address='1'),
           AutoLoadResource(model='Generic Module',name= 'Module 1',relative_address= '1/1'),
           AutoLoadResource(model='Generic Port',name= 'Port 1', relative_address='1/1/1'),
           AutoLoadResource(model='Generic Port', name='Port 2', relative_address='1/1/2'),
           AutoLoadResource(model='Generic Power Port', name='Power Port', relative_address='1/PP1')]


           attributes = [ AutoLoadAttribute(relative_address='', attribute_name='Location', attribute_value='Santa Clara Lab'),
                          AutoLoadAttribute('', 'Model', 'Catalyst 3850'),
                          AutoLoadAttribute('', 'Vendor', 'Cisco'),
                          AutoLoadAttribute('1', 'Serial Number', 'JAE053002JD'),
                          AutoLoadAttribute('1', 'Model', 'WS-X4232-GB-RJ'),
                          AutoLoadAttribute('1/1', 'Model', 'WS-X4233-GB-EJ'),
                          AutoLoadAttribute('1/1', 'Serial Number', 'RVE056702UD'),
                          AutoLoadAttribute('1/1/1', 'MAC Address', 'fe80::e10c:f055:f7f1:bb7t16'),
                          AutoLoadAttribute('1/1/1', 'IPv4 Address', '192.168.10.7'),
                          AutoLoadAttribute('1/1/2', 'MAC Address', 'te67::e40c:g755:f55y:gh7w36'),
                          AutoLoadAttribute('1/1/2', 'IPv4 Address', '192.168.10.9'),
                          AutoLoadAttribute('1/PP1', 'Model', 'WS-X4232-GB-RJ'),
                          AutoLoadAttribute('1/PP1', 'Port Description', 'Power'),
                          AutoLoadAttribute('1/PP1', 'Serial Number', 'RVE056702UD')]

           return AutoLoadDetails(sub_resources,attributes)
        '''

        resources = []
        attributes = []

        ssh, channel, _ = self._connect(context)

        show_version = self._ssh_command(context, ssh, channel, 'show version', ' # ')
        header2attr = {
            'Version summary': 'OS Version',
            'Product model': 'Model',
            # 'System serial num': 'Serial Number',

        }
        for line in show_version.split('\n'):
            line = line.strip()
            for header in header2attr:
                if line.startswith(header + ':'):
                    value = line.split(header + ':')[1].strip().replace('\\"', '')
                    attributes.append(AutoLoadAttribute('', header2attr[header], value))


        header2attr = {
            'HW address': 'MAC Address',
            'Mac address': 'MAC Address',
            'MTU': 'MTU',
            'Speed': 'Bandwidth',
            'Actual speed': 'Bandwidth',
            'Duplex': 'Duplex',
            'IP address': 'IPv4 Address',
            'IPv6 address': 'IPv6 Address',
            'Comment': 'Port Description',
            'Description': 'Port Description',
        }

        show_interfaces = self._ssh_command(context, ssh, channel, 'show interfaces', ' # ')

        chassis = set()
        modules = set()
        addr = 'BAD_ADDR'
        for line in show_interfaces.split('\n'):
            if line.startswith('Interface '):
                addr0 = line.strip().split(' ')[1]
                addr = '1/' + addr0
                if '1' not in chassis:
                    chassis.add('1')
                    resources.append(AutoLoadResource(model='Generic Chassis', name='Chassis 1',    relative_address='1'))
                resources.append(AutoLoadResource(model='Generic Port',        name=addr0,          relative_address=addr))
            elif line.startswith('Eth'):
                addr = line.strip().replace('Eth', '')
                aa = addr.split('/')
                if len(aa) == 2:
                    if aa[0] not in chassis:
                        chassis.add(aa[0])
                        resources.append(AutoLoadResource(model='Generic Chassis',     name='Chassis ' + aa[0],  relative_address=aa[0]))
                    resources.append(AutoLoadResource(model='Generic Port',        name='Port ' + aa[1],         relative_address=addr))
                elif len(aa) == 3:
                    if aa[0] not in chassis:
                        chassis.add(aa[0])
                        resources.append(AutoLoadResource(model='Generic Chassis',     name='Chassis ' + aa[0],      relative_address=aa[0]))
                    if aa[0] + '/' + aa[1] not in modules:
                        modules.add(aa[0] + '/' + aa[1])
                        resources.append(AutoLoadResource(model='Generic Module',      name='Module ' + aa[1],       relative_address=aa[0] + '/' + aa[1]))
                    resources.append(AutoLoadResource(model='Generic Port',        name='Port ' + aa[2],         relative_address=addr))
                else:
                    self._log(context, 'Unhandled address format ' + addr)
            else:
                line = line.strip()
                for header in header2attr:
                    if line.startswith(header + ':'):
                        value = line.split(header + ':')[1].strip()
                        value = value.replace(' Mbps', '')
                        value = value.replace(' Gbps', '000')
                        value = value.replace('Mb/s', '')
                        value = value.replace('Gb/s', '000')
                        if header == 'MTU':
                            value = value.split(' ')[0]
                            if not value:
                                continue
                        value = value.replace(' (auto)', '')
                        value = value.replace('N\\A', '')
                        value = value.replace('N/A', '')
                        if value == 'full':
                            value = 'Full'
                        if value == 'half':
                            value = 'Half'
                        if header2attr[header] == 'Duplex' and not value:
                            value = 'Full'
                        if header2attr[header] == 'Bandwidth' and not value:
                            continue
                        attributes.append(AutoLoadAttribute(addr, header2attr[header], value))


        rv = AutoLoadDetails(resources, attributes)
        self._disconnect(context, ssh, channel)
        return rv

    # </editor-fold>

    # <editor-fold desc="Health Check">

    def health_check(self,cancellation_context):
        """
        Checks if the device is up and connectable
        :return: str: Success or fail message
        """
        pass

    # </editor-fold>

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass
