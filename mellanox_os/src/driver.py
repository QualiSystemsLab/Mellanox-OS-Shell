import json
import os
import time
import paramiko
import re

##########################################
# Add bugfix that was not released yet
# This must be above import statements for cloudshell.networking.*
# https://github.com/QualiSystems/cloudshell-networking/blob/dev/cloudshell/networking/apply_connectivity/models/connectivity_request.py
import cloudshell


def bugfix():  # pragma: no cover
    fn = os.path.join(os.path.dirname(cloudshell.__file__), 'networking', 'apply_connectivity', 'models', 'connectivity_request.py')
    with open(fn, 'r') as f:
        s = f.read()
    if "con_params = ConnectionParams()" in s and "dictionary['vlanId']" not in s:
        s = s.replace("con_params = ConnectionParams()",
                      "con_params = ConnectionParams(); con_params.vlanId = dictionary['vlanId']")
        with open(fn, 'w') as g:
            g.write(s)

bugfix()

##########################################


from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.context import AutoLoadCommandContext, InitCommandContext, ResourceCommandContext, \
    AutoLoadResource, AutoLoadAttribute, AutoLoadDetails
from cloudshell.shell.core.context_utils import get_attribute_by_name

from cloudshell.networking.apply_connectivity.apply_connectivity_operation import apply_connectivity_changes, \
    ConnectivityActionRequest, DriverResponseRoot
from cloudshell.networking.apply_connectivity.models.connectivity_result import ConnectivitySuccessResponse, \
    ConnectivityErrorResponse

from cloudshell.core.logger.qs_logger import get_qs_logger


class SSHManager:
    def __init__(self, logger, host, port, username, password, prompt_regex):
        self.logger = logger
        self.logger.info('connect %s %d %s %s %s' % (host, port, username, password, prompt_regex))
        self.ssh = paramiko.SSHClient()
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.ssh.connect(host,
                         port=port,
                         username=username,
                         password=password,
                         look_for_keys=True)

        self.channel = self.ssh.invoke_shell(term='console', width=300, height=100000)
        self._read(prompt_regex)  # eat banner

    def disconnect(self):
        self.logger.info('disconnnect')
        self.ssh.close()

    def _write(self, command):
        self.logger.info('sending: <<<' + command + '>>>')
        self.channel.send(command)
        self.logger.info('send complete')

    def _read(self, prompt_regex):
        buf = ''
        self.logger.info('read...')
        while True:
            self.logger.info('recv')
            r = self.channel.recv(2048)
            self.logger.info('recv returned: <<<' + str(r) + '>>>')
            if r:
                buf += r

            # if isinstance(r, str):
            #     buf += r
            # elif r is None:
            #     continue
            # else:
            #     return ''

            if buf:
                cleanbuf = buf
                cleanbuf = re.sub(r'(\x9b|\x1b)[[?;0-9]*[a-zA-Z]', '', cleanbuf)
                cleanbuf = re.sub(r'(\x9b|\x1b)[>=]', '', cleanbuf)
                cleanbuf = re.sub('.\b', '', cleanbuf)  # not r''
            else:
                cleanbuf = ''
            if not r or len(re.findall(prompt_regex, cleanbuf)) > 0:
                if cleanbuf:
                    cleanbuf = cleanbuf.replace('\r', '\n')
                self.logger.info('\n\nread complete: <<<' + str(cleanbuf) + '>>>\n\n')
                return cleanbuf

    def command(self, command, prompt_regex):
        self._write(command + '\n')
        rv = self._read(prompt_regex)
        if '\n%' in rv.replace('\r', '\n'):
            es = 'CLI error message: ' + rv
            self.logger.info(es)
            raise Exception(es)
        return rv


def decrypt_password(context, encrypted_password):
    """

    :param context: ResourceCommandContext | AutoLoadCommandContext
    :param encrypted_password: str
    :rtype: str
    """
    try:
        domain = context.reservation.domain
    except:
        domain = 'Global'

    api = CloudShellAPISession(context.connectivity.server_address,
                               token_id=context.connectivity.admin_auth_token,
                               port=context.connectivity.cloudshell_api_port,
                               domain=domain)
    return api.DecryptPassword(encrypted_password).Value


def get_logger_from_context(context):
    """

    :param context: ResourceCommandContext | AutoLoadCommandContext
    :rtype: Logger
    """
    try:
        resid = context.reservation.reservation_id
    except:
        resid = 'out-of-reservation'
    try:
        resourcename = context.resource.fullname
    except:
        resourcename = 'no-resource'
    return get_qs_logger(resid, 'Mellanox-OS-L2', resourcename)


class MellanoxOsDriver(ResourceDriverInterface):
    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        self.ssh_manager = None

    def initialize(self, context, ssh_manager=None):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        :param ssh_manager SSHManager: fake SSH manager for unit tests
        """
        self.ssh_manager = ssh_manager
        return 'Finished initializing'

    # <editor-fold desc="Connectivity Provider Interface (Optional)">

    # The ApplyConnectivityChanges function is intended to be used for using switches as connectivity providers
    # for other devices. If the Switch shell is intended to be used a DUT only there is no need to implement it

    def ApplyConnectivityChanges(self, context, request):
        """
        Configures VLANs on multiple ports or port-channels
        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param str request: A JSON object with the list of requested connectivity changes
        :return: a json object with the list of connectivity changes which were carried out by the switch
        :rtype: DriverResponseRoot
        """

        logger = get_logger_from_context(context)
        logger.info('Request: %s' % request)

        sshs = self.ssh_manager or SSHManager(logger,
                          context.resource.address,
                          22,
                          get_attribute_by_name(context=context, attribute_name='User'),
                          decrypt_password(context, get_attribute_by_name(context=context, attribute_name='Password')),
                          ' > ')

        o = sshs.command('enable', ' # |ssword:')
        if 'ssword:' in o:
            enable_password = decrypt_password(context,
                                               get_attribute_by_name(context=context, attribute_name='Enable Password'))
            sshs.command(enable_password, ' # ')

        try:
            sshs.command('configure terminal', ' # ')
            parking_vlan = '2098'
            try:
                def add_vlan_handler(qr):
                    """
                    :param qr: ConnectivityActionRequest
                    :return: ConnectivityActionResult
                    """
                    if False:
                        qr = ConnectivityActionRequest()
                    try:
                        addr = '/'.join(qr.actionTarget.fullAddress.split('/')[1:])
                        vlan = qr.connectionParams.vlanId
                        sshs.command('vlan %s' % vlan, ' # ')
                        sshs.command('exit', ' # ')
                        sshs.command('interface ethernet %s switchport mode access' % addr, ' # ')
                        sshs.command('interface ethernet %s switchport access vlan %s' % (addr, vlan), ' # ')
                        return ConnectivitySuccessResponse(qr, 'Success')
                    except Exception as e:
                        return ConnectivityErrorResponse(qr, str(e))

                def remove_vlan_handler(qr):
                    """
                    :param qr: ConnectivityActionRequest
                    :return: ConnectivityActionResult
                    """
                    try:
                        if False:
                            qr = ConnectivityActionRequest()
                        addr = '/'.join(qr.actionTarget.fullAddress.split('/')[1:])
                        vlan = qr.connectionParams.vlanId
                        sshs.command('interface ethernet %s switchport access vlan %s' % (addr, parking_vlan), ' # ')
                        try:
                            sshs.command('no vlan %s' % vlan, ' # ')
                        except:
                            logger.info('Ignoring the error from "no vlan %s"' % vlan)
                        return ConnectivitySuccessResponse(qr, 'Success')
                    except Exception as e:
                        return ConnectivityErrorResponse(qr, str(e))

                return apply_connectivity_changes(request=request,
                                                  add_vlan_action=add_vlan_handler,
                                                  remove_vlan_action=remove_vlan_handler)
            finally:
                sshs.command('exit', ' # ')
        finally:
            sshs.disconnect()

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


        def MakeAutoLoadResource(model, name, relative_address, unique_identifier=None):
            rv = AutoLoadResource()
            rv.model = model
            rv.name = name
            rv.relative_address = relative_address
            rv.unique_identifier = unique_identifier
            return rv

        def MakeAutoLoadAttribute(relative_address, attribute_name, attribute_value):
            rv = AutoLoadAttribute()
            rv.relative_address = relative_address
            rv.attribute_name = attribute_name
            rv.attribute_value = attribute_value
            return rv

        resources = []
        attributes = []

        logger = get_logger_from_context(context)

        sshs = self.ssh_manager or SSHManager(logger,
                          context.resource.address,
                          22,
                          get_attribute_by_name(context=context, attribute_name='User'),
                          decrypt_password(context, get_attribute_by_name(context=context, attribute_name='Password')),
                          ' > ')

        show_version = sshs.command('show version', ' > ')
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
                    attributes.append(MakeAutoLoadAttribute('', header2attr[header], value))

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

        show_interfaces = sshs.command('show interfaces', ' > ')

        chassis = set()
        modules = set()
        addr = 'BAD_ADDR'

        for line in show_interfaces.split('\n'):
            if line.startswith('Interface '):
                addr0 = line.strip().split(' ')[1]
                addr = '1/' + addr0
                if '1' not in chassis:
                    chassis.add('1')
                    resources.append(
                        MakeAutoLoadResource(model='Generic Chassis', name='Chassis 1', relative_address='1'))
                resources.append(MakeAutoLoadResource(model='Generic Port', name=addr0, relative_address=addr))
            elif line.startswith('Eth'):
                addr = line.strip().replace('Eth', '')
                aa = addr.split('/')
                if len(aa) == 2:
                    if aa[0] not in chassis:
                        chassis.add(aa[0])
                        resources.append(MakeAutoLoadResource(model='Generic Chassis', name='Chassis ' + aa[0],
                                                              relative_address=aa[0]))
                    resources.append(
                        MakeAutoLoadResource(model='Generic Port', name='Port ' + aa[1], relative_address=addr))
                elif len(aa) == 3:
                    if aa[0] not in chassis:
                        chassis.add(aa[0])
                        resources.append(MakeAutoLoadResource(model='Generic Chassis', name='Chassis ' + aa[0],
                                                              relative_address=aa[0]))
                    if aa[0] + '/' + aa[1] not in modules:
                        modules.add(aa[0] + '/' + aa[1])
                        resources.append(MakeAutoLoadResource(model='Generic Module', name='Module ' + aa[1],
                                                              relative_address=aa[0] + '/' + aa[1]))
                    resources.append(
                        MakeAutoLoadResource(model='Generic Port', name='Port ' + aa[2], relative_address=addr))
                else:
                    logger.error('Unhandled address format ' + addr)
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
                        attributes.append(MakeAutoLoadAttribute(addr, header2attr[header], value))

        sshs.disconnect()

        rv = AutoLoadDetails()
        rv.resources = resources
        rv.attributes = attributes
        return rv

    # </editor-fold>

    # <editor-fold desc="Health Check">

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass
