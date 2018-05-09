#!/usr/bin/python

#
# Configures networking for the controller.
#


def module_exists(module_name):
    try:
        __import__(module_name)
    except ImportError:
        return False
    else:
        return True


def executing_on_installer():
    if module_exists("pyvmomi_tools.extensions"):
        return True
    else:
        return False

from pyVmomi import vim
from pyVim import connect
import sys
import subprocess
import time
import json
import logging
import base64
from logging.handlers import RotatingFileHandler  # noqa
import os
import socket
import re
import random
import string
import traceback
import urlparse
import ssl
import StringIO
from ConfigParser import SafeConfigParser
from threading import Thread
sys.path.append("/usr/share/springpath/storfs-misc/")
from springpath_env_parse import parseEnvVariableTunes


if module_exists("pyvmomi_tools.extensions"):
    from pyvmomi_tools.extensions import task
    import paramiko
else:
    from pyVim import task
    task.wait_for_task = task.WaitForTask

DIR_TMP = '/tmp'
DIR_LOG = '/var/log'
DIR_LOG_SPRINGPATH = '/var/log/springpath'
FILE_LOG = 'network_setup.log'
LOG_FILE_MAX_BYTE_COUNT = 10000000
LOG_FILE_BACKUP_COUNT = 10
USER_CTL_PWD = None

def getVmnicInfo(host, isExternalStorageEnabled=False):
    """
        Get pci and pmnics ordered by pci
        args:
            host: vim.HostSystem object
            isExternalStorageEnabled: Flag to indicate if external storage is enabled
        returns:
            vswitch_info: dictionary with pmnics
    """
    vswitch_info = {"vswitch_mgmt": {}, "vswitch_storage_data": {}, "vswitch_vmotion": {}, \
                    "vswitch_vmnetwork": {}}

    if isExternalStorageEnabled:
        vswitch_info.update({"vswitch_iscsi": {}})

    pci_vmnics = {}
    for pnic in host.config.network.pnic:
        pci_vmnics[pnic.pci] = pnic.device

    o_pci_vmnics = collections.OrderedDict(sorted(pci_vmnics.items()))

    expected_pnics = 8 #default
    if isExternalStorageEnabled:
        expected_pnics = 10

    if len(o_pci_vmnics) > 7:
        for section in vswitch_info:
            if section == "vswitch_mgmt":
                vswitch_info[section]['pnic_a'] = o_pci_vmnics.values()[0]
                vswitch_info[section]['pnic_b'] = o_pci_vmnics.values()[1]
            elif section == "vswitch_storage_data":
                vswitch_info[section]['pnic_a'] = o_pci_vmnics.values()[2]
                vswitch_info[section]['pnic_b'] = o_pci_vmnics.values()[3]
            elif section == "vswitch_vmnetwork":
                vswitch_info[section]['pnic_a'] = o_pci_vmnics.values()[4]
                vswitch_info[section]['pnic_b'] = o_pci_vmnics.values()[5]
            elif section == "vswitch_vmotion":
                vswitch_info[section]['pnic_a'] = o_pci_vmnics.values()[6]
                vswitch_info[section]['pnic_b'] = o_pci_vmnics.values()[7]
            elif section == "vswitch_iscsi" and isExternalStorageEnabled:
                vswitch_info[section]['pnic_a'] = o_pci_vmnics.values()[8]
                vswitch_info[section]['pnic_b'] = o_pci_vmnics.values()[9]
    else:
        logging.debug("Not sufficient pnics on host: {}. {} pnics are expected".format(host.name, expected_pnics))

    return vswitch_info

def isHXHardware(esx_host, esx_user, esx_pwd):
    """
    Determine if we are configuring HX-based ESXi host
    by checking if first 8 vmnics description contains "Cisco VIC"
    """

    ssh = paramiko.SSHClient()
    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(esx_host, username=esx_user, password=esx_pwd)
        cmd = "esxcli network nic list | sort -k2 | grep \"" + getHXNicGrepString() + "\" | wc -l"
        logging.debug("Running remote SSH command on ESXi: {}".format(cmd))

        stdin, stdout, stderr = ssh.exec_command(cmd)
        while not stdout.channel.exit_status_ready():
            time.sleep(1)

        # Check first 8 vmnics
        if stdout.channel.exit_status != 0 or int(str(stdout.readline(2048))) < 8:
            return False
        else:
            return True

    except:
        ex = sys.exc_info()
        logging.exception(
            "Failed to execute esxcli network nic list command remotely on ESX host: {}, {}, {}".format(esx_host,
                                                                                                        ex[0], ex[1]))
    finally:
        ssh.close()

# TODO JSON THRIFT Parse - vSwitches, ESX user/pwd, controller user/pwd,
#           whether hosts are in VDS config, whether to create vMotion port, force remove vMotion port,
#           perform already configured pre-check, DNS host, DNS search
#
# TODO Install script on deployment device.
# TODO Refine JSON file format
# TODO Use argparse library?
# TODO Add more comprehensive validateSetup
# TODO When attaching host vnic with address already is use on another vnic should we skip or exit script?
# TODO ensure that VMK0 is set on same vlan and PG as VM IP (validation framework)
# TODO Handle case where VMKernel PG with same IP on VDS and switching to Std config or vice-versa?
# TODO Check Subnetmask, Gateway, hostname, DNS host, DNS search when checking if controller already configured (hard reset = false).
# TODO Output errors in step states.
# TODO Catch exceptions and handle them
# TODO Run controller configuration in parallel
# TODO Prompt for vCenter password if not provided
# TODO Get subnet mask and gateway from existing controller when auto-detect from existing cluster


def isValidIP4Address(strIP):
    '''
    Checks to verify if have a valid IP address. This means
    that the IP falls with the range of 0.0.0.0 and 255.255.255.255
    but is not 0.0.0.0 or in the range of 169.254.0.1 through 169.254.255.254
    (this is a range linux/esxi auto-assigns when DHCP fails to assign an address)
    '''

    pat_valid_ip = re.compile(r'^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$')
    pat_no_dhcp_ip = re.compile(r'^169\.254\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([1]?[1-9]?[1-9]|2[0-4][0-9]|25[0-4])$')
    pat_zero_ip = re.compile(r'^0\.0\.0\.0$')

    if pat_zero_ip.match(strIP):
        logging.debug("We have a zero IP address. DHCP assignment may have failed! IP address: " + strIP)
        return False
    elif pat_no_dhcp_ip.match(strIP):
        logging.debug("We have a non-routeable IP address. DHCP assignment may have failed! IP address: " + strIP)
        return False
    elif pat_valid_ip.match(strIP):
        logging.debug("We have an valid IP address. IP address: " + strIP)
        return True
    else:
        logging.debug("We have an invalid IP address! IP address: " + strIP)
        return False


class SpringpathNetworkingSetup_VCenter:

    # Configurable constants
    # ----------------------

    # Thrift exception ID's

    STEXCEPTIONID_INTERNAL_ERROR = 1
    STEXCEPTIONID_SYSTEM_ERROR = 2
    STEXCEPTIONID_INVALID_ARGUMENT = 3
    STEXCEPTIONID_NOT_SUPPORTED = 7
    STEXCEPTIONID_CLUSTER_INVALID_STATE = 105

    # Thrift output status code

    STEP_STATE_NOTSTARTED = 0
    STEP_STATE_INPROGRESS = 1
    STEP_STATE_SUCCEEDED = 2
    STEP_STATE_FAILED = 3

    # Thrift entity type constants

    ENTITY_TYPE_PNODE = 2
    ENTITY_TYPE_NODE = 3
    ENTITY_TYPE_CLUSTER = 4
    ENTITY_TYPE_DATASTORE = 5
    ENTITY_TYPE_VIRTNODE = 6
    ENTITY_TYPE_VIRTCLUSTER = 7
    ENTITY_TYPE_VIRTDATASTORE = 8
    ENTITY_TYPE_VIRTMACHINE = 9

    STCTLVM_PREFIX = "STCTLVM"
    WAIT_TIME = 10  # ten seconds
    MAX_RETRIES = 120  # This number is larger to accommodate the root device movement use-case.
    WAIT_FOR_REBOOT = 240  # After host reboot, wait time before checking availability

    # Thrift role type constants

    ROLE_TYPE_UNSPECIFIED = 0
    ROLE_TYPE_STORAGE = 1
    ROLE_TYPE_COMPUTE = 2
    ROLE_TYPE_CACHE = 3
    ROLE_TYPE_ALL = 4

    # JSON config file locations

    JSON_CONFIG_FILE = None
    JSON_CONFIG_FILE_NETWORKING = None
    JSON_CONFIG_FILE_VCENTER = None

    # TUNES files

    ENV_VARIABLES_FILE_DEFAULT = "/opt/springpath/springpath_default.tunes"
    ENV_VARIABLES_FILE_CUSTOM_CLUSTER = "/opt/springpath/springpath_custom_cluster.tunes"
    ENV_VARIABLES_FILE_CUSTOM_NODE = "/opt/springpath/springpath_custom_node.tunes"

    # vCenter parameters

    VCENTER_HOST = None
    VCENTER_DATACENTER = None
    VCENTER_CLUSTER = None
    VCENTER_USER = None
    VCENTER_PWD = None

    # management network parameters

    VSWITCH_CTL_MGMT = "vSwitch0"
    VSWITCH_CTL_MGMT_DEFAULT = "vSwitch0"
    PNIC_CTL_MGMT = None
    PG_CTL_MGMT = "Storage Controller Management Network"
    VLANID_CTL_MGMT = 0
    VNIC_LABEL_CTL_MGMT = "Springpath Storage Management Network Adapter"
    VNIC_SUMMARY_CTL_MGMT = "Springpath Storage Management Network Adapter"
    NET_MASK_CTL_MGMT = None
    GATEWAY_CTL_MGMT = None
    IFC_MGMT = "eth0"
    IFC_MGMT_NAME = "mgmt-if"
    IP_CTL_MGMT = []
    IP_ESX_MGMT = []
    ESX_ROLE_MAP = {}

    # data network parameters

    VSWITCH_CTL_DATA = "vSwitch1"
    PNIC_CTL_DATA = None
    PG_CTL_DATA = "Storage Controller Data Network"
    VLANID_CTL_DATA = 0
    VNIC_LABEL_CTL_DATA = "Springpath Storage Data Network Adapter"
    VNIC_SUMMARY_CTL_DATA = "Springpath Storage Data Network Adapter"
    NET_MASK_CTL_DATA = None
    GATEWAY_CTL_DATA = None
    IFC_DATA = "eth1"
    IFC_DATA_NAME = "data-if"
    IP_CTL_DATA = []
    IP_ESX_DATA = []
    PG_ESX_DATA = "Storage Hypervisor Data Network"  # "Springpath VMKernel Data Network"
    MTU_DATA = None

    # vMotion network parameters

    VSWITCH_VMOTION = parseEnvVariableTunes("vswitch_vmotion.vswitch")
    VLANID_VMOTION = 0
    PG_ESX_VMOTION = "Hypervisor vMotion Network"
    MTU_VMOTION = None

    # VM network parameters

    VSWITCH_VMNETWORK = parseEnvVariableTunes("vswitch_vmnetwork.vswitch")
    PG_INFO_LIST_VMNETWORK = []

    # iSCSI network parameters

    VSWITCH_ISCSINETWORK = parseEnvVariableTunes("vswitch_iscsi.vswitch")
    PG_INFO_LIST_ISCSINETWORK = []
    EXTERNAL_STORAGE_ENABLED = False

    # vswitch info empty dictionary
    VSWITCH_INFO = {"vswitch_mgmt": {}, "vswitch_storage_data": {}, "vswitch_vmotion": {}, \
                    "vswitch_vmnetwork": {}}

    # HX Replication network parameters
    PG_CTL_REPL_NWK = parseEnvVariableTunes("replication_nwk.portgroup")
    VLANID_CTL_REPL_NWK = 0
    VNIC_LABEL_CTL_REPL_NWK = parseEnvVariableTunes("replication_nwk.vnic_label")
    VNIC_SUMMARY_CTL_REPL_NWK = parseEnvVariableTunes("replication_nwk.vnic_summary")
    IFC_CTL_REPL_NWK_NAME = "repl-if"

    VSWITCH_RENAME_SCRIPT = "/opt/springpath/storfs-deploy/ansible/vswitch_config.sh"

    DEV_TYPE_E1000 = "VirtualE1000"
    DEV_TYPE_VVMXNET3 = "VirtualVmxnet3"

    ESX_HOST_LIST = []
    DNS_HOST_LIST = []
    DNS_SEARCH_LIST = []

    CTL_USER = parseEnvVariableTunes("credentials.stctl_vm_uname")
    CTL_PWD = parseEnvVariableTunes("credentials.stctl_vm_passwd")
    ESX_USER = "root"
    ESX_PWD = ""

    NUM_PG_PORTS = 32
    CREATE_VMKERNEL_DATA_PORTGROUP = True
    VDS_CONFIGURATION = False
    FORCE_MOVE_VM_PORTGROUP = False
    FORCE_MOVE_VMKERNEL_PORTGROUP = False
    HARD_RESET = False
    POWER_ON_ESX = True
    CONFIG_PARAMS_FROM_EXISTING_CLUSTER = False
    HOSTNAME_COMMENT = '# DO NOT TOUCH. Added by Springpath Deployment.'

    CONFIGURE_MODE = 'complete'
    CONFIGURE_MODE_OPTION_COMPLETE = 'complete'
    CONFIGURE_MODE_OPTION_VM_PORT_GROUP = 'vm_port_group'

    HARDWARE_TYPE_INVENTORY = 0
    HARDWARE_TYPE_INVENTORY_UNKNOWN = 1
    HARDWARE_TYPE_INVENTORY_HX = 2
    HARDWARE_TYPE_INVENTORY_NON_HX = 3
    HARDWARE_TYPE_INVENTORY_MIXED = 4

    HX_SERVICE_PROFILE_TEMPLATES = ['hx-nodes', 'compute-nodes']
    FACTORY_MODE = False

    # Constructor
    # -----------

    def __init__(self, enable_logging=True):

        self.si = None
        self.datacenter = None
        self.configured_host_ctl_pairs = []
        self.cached_host_list = None
        self.cached_vm_list = None

        if enable_logging:
            self._enableLogging()

    # Public methods
    # ---------------

    def usage(self):
        """
        This script sets Springpath controller networking and
        optionally the ESXi data path networking
        as needed by the Springpath appliance ("vMotion" port group).

        It takes the following arguments:

        --vcenter-host - vCenter host to connect for configuration. Used only if configuring from vCenter.
        --vcenter-datacenter - vCenter datacenter under which to configure networking. Used only if configuring from vCenter.
        --vcenter-cluster - Existing vCenter cluster from which to auto-configure network parameters (vSwitch, Is in VDS, vlan ID's, gateway, subnet). (if not specified, will not auto-configure)
        --vcenter-user - vCenter user name with admin privileges. Used only if configuring from vCenter.
        --vcenter-password - vCenter password for the vCenter user. Used only if configuring from vCenter.
        --esx-user - ESXi user name (defaults to "root"). Used only if configuring directly from ESXi
        --esx-password - ESXi password (defaults to "sp"). Used only if configuring directly from ESXi
        --ctl-user - controller user (defaults to "root")
        --ctl-password - controller password (defaults to "sp")
        --vlanid-mgmt - vlan ID for the Springpath management network (defaults to 0)
        --vswitch-mgmt - vswitch ID for the Springpath management network
        --netmask-mgmt - network mask for the Springpath management network
        --gateway-mgmt - gateway for the Springpath management network
        --vlanid-data - vlan ID for the Springpath data network  (defaults to 0)
        --vswitch-data - vswitch ID for the Springpath data network
        --netmask-data - network mask for the Springpath data network
        --gateway-data - gateway for the Springpath data network
        --esx-host-list - list of ESX hosts to configure (as named in vCenter)
        --dns-host-list - list of DNS servers to be used by the cluster (optional)
        --dns-search-list - list of DNS search strings (optional)
        --ip-ctl-mgmt-list - static IP list of controllers for the mgmt network (optional, defaults to DHCP)
        --ip-ctl-data-list - static IP list of controllers for the data network (optional, defaults to DHCP)
        --ip-esx-data-list - static IP list of esx hosts for the data network (optional, defaults to DHCP)
        --force-move-vm-portgroup - whether to "force" remove any non-controller VMs from Storage controller port groups in order to move them (defaults to FALSE)
        --force-move-vmkernel-portgroup - whether to "force" remove existing ESXi vnics and/or delete existing vMotion port group in order re-create on different vSwitch (defaults to FALSE)
        --hard-reset - if false, script attempts to determine if VM is already configured and if so, does not re-configure
        --create-vmkernel-data-pg - whether or not to create the ESX vmkernel data port group and set it's IP (defaults to FALSE)
        --vds-configuration - whether or not to setup with VDS switches (defaults to FALSE)
        --configure-mode - what part of network configuration to run (defaults to 'complete', other option is 'vm_port_group')

        OR

        --json-config-file - location of end-user JSON config. file. If this is specified, all input will come from this file except vCenter user and password.
        --vcenter-user - vCenter user name with admin privileges. Used only if configuring from vCenter.
        --vcenter-password - vCenter password for the vCenter user. Used only if configuring from vCenter.
        --configure-mode - what part of network configuration to run (defaults to 'complete', other option is 'vm_port_group')

        OR

        --json-config-file-vcenter - location of end-user JSON vCenter config. file. If specified, all other arguments are ignored "json-config-file-networking"
        --json-config-file-networking - location of end-user JSON networking config. file. If specified, all other arguments are ignored except "json-config-file-vcenter"
        --configure-mode - what part of network configuration to run (defaults to 'complete', other option is 'vm_port_group')

        If using an end-user JSON file (--json-config-file parameter), the format of this file should include the following:

        {
          "clusterName": "samir_cluster1",
          "clusterIp": "sysmgmt007-cluster",
          "clusterConfig": {
            "dataReplicationFactor": 2,
            "clusterAccessPolicy": "strict"
          },
          "managementIp": "sysmgmt007-cluster-m",
          "vCenter": {
              "url": "sysmgmt007-vc",
              "ssoUrl": "",
              "clustername": "samir_cluster1",
              "datacenter": "samir_dc1"
          },
          "ipAddresses": [
            {
              "controller": "sysmgmt007-stctlvm-1a",
              "dataNetwork": "sysmgmt007a-v",
              "hypervisor": "sysmgmt007-esx-1a",
              "ipmi": "sysmgmt007-esx-1a-m",
              "management": ""
            },
            {
              "controller": "sysmgmt007-stctlvm-1b",
              "dataNetwork": "sysmgmt007b-v",
              "hypervisor": "sysmgmt007-esx-1b",
              "ipmi": "sysmgmt007-esx-1b-m",
              "management": ""
            },
            {
              "controller": "sysmgmt007-stctlvm-1c",
              "dataNetwork": "sysmgmt007c-v",
              "hypervisor": "sysmgmt007-esx-1c",
              "ipmi": "sysmgmt007-esx-1c-m",
              "management": ""
            }
          ],
          "subnetMask": {
            "controllerAndvMotion": "255.255.248.0",
            "hypervisorAndipmi": "255.255.248.0"
          },
          "gateway": {
            "controllerAndvMotion": "10.64.248.1",
            "hypervisorAndipmi": "10.64.16.1"
          },
          "vlan": {
            "controllerAndvMotion": 0,
            "hypervisorAndipmi": 0
          },
          "is_vds": {
            "controllerAndvMotion": true,
            "hypervisorAndipmi": true
           },
          "vSwitch": {
            "controllerAndvMotion": "vDSwitch1",
            "hypervisorAndipmi": "vDSwitch0"
          },
          "dnsServers": ["10.64.1.8", "10.64.1.9"],
          "dnsSearch": ["eng.springpath.com"],
          "ntpServers": ["ntp1.eng.storvisor.com"],
          "smtpServer": "mailhost.eng.storvisor.com",
          "fromAddress": "samir@springpathinc.com",
          "timeZone": "America/Los_Angeles",
          "enableAutoSupport": "false"
        }

        Additional parameters may be present in the JSON file but will be ignored.

        This script will do the following:

        1. Reset UDEV rules
        2. Reset controller IP settings.
        3. Power down controller and detach all Springpath controller vnics.
        4. Remove (if needed) and add VM port group "Storage Controller Management Network" (for eth0 of controller)
        5. Re-attach controller vnic to VM port group "Storage Controller Management Network"
        6. Remove (if needed) and add a VM port group "Storage Controller Data Network" (for eth1 of controller)
        7. Re-attach controller vnic to VM port group "Storage Controller Data Network"
        8. Setup VMKernel port group ("vMotion") and it's IP settings (if needed)

        If "create-vmkernel-data-pg" is True, the following will also be performed (step 8 above):

        1. Delete any existing Springpath VMKernel port group ("vMotion") if on different vswitch than the specified data vswitch. It will only
        delete a VDS portgroup if setting VDS configuration and standard port group if settings standard configuration.
        2. Recreate the Springpath VMKernel port group ("vMotion") on specified vswitch (if not created already).
        3. Attach specified hosts to the VMKernel port group setting the data static IP (if specified).

        Pre-requisites to configure VDS setup is as follows:
        1. The VDS switches must be pre-created in vCenter under the specified datacenter.
        2. The hosts must be added to vCenter under the specified datacenter.
        3. Hosts must already be added to the management and data vSwitches (proxy switches should have uplinks setup)
        4. A VMKernel portgroup must be attached to the management vSwitch.
        5. Another VMKernel port group should not already exist with the same data IP if setting up the VMKernel port group, unless
           it is already on the same data port group as specified.

        Pre-requisites to configure "standard" setup is as follows:
        1. The standard switches must be pre-created on every ESXi host specified.
        2. A VMKernel portgroup must be attached to the management vSwitch.
        3. The hosts must all be in vCenter or none of them should be in vCenter.
        4. Another VMKernel port group should not already exist with the same data IP if setting up the VMKernel port group, unless
           it is already on the same data port group as specified.


        Logging: Debug and error output will be logged to either /var/log/network_setup.log,
         /var/log/springpath/network_setup.log, or /tmp/network_setup.log depending on available
         directories.
        """
        print self.usage.__doc__

    def configureNetworking(self):

        try:
            self._parseCmdLineArgs()
            self._setTuneBasedVariables()
            self._validateAndPrintParameters()

            if SpringpathNetworkingSetup_VCenter.CONFIG_PARAMS_FROM_EXISTING_CLUSTER:
                self._autoDiscoverNetworkParamsFromExistingCluster()

            # Only determine hardware type
            # if executing on installer. Later
            # can support this from ESXi
            if executing_on_installer():
                self.initializeHardwareTypeInventory()

            if self._hostsFoundInVCenter():
                self.configureNetworkingFromVCenter()
            else:
                self.configureNetworkingFromESX()

        except SystemExit:
            raise
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.error(traceback.format_exception(exc_type, exc_value, exc_traceback))
            sys.stderr.write("Configure networking script generated an exception: {0}".format(exc_value))
            sys.exit(1)

    def resetScript(self):

        if self.si:
            connect.Disconnect(self.si)
            self.si = None
            self.datacenter = None
            self.cached_host_list = None
            self.cached_vm_list = None
            self.configured_host_ctl_pairs = []

    def configureNetworkingFromESX(self):
        """
        Configures Springpath networking via ESXi by doing the following:
        1. Initialize Access to ESXi
        2. Reset UDEV rules
        3. Reset controller IP settings.
        4. Power down controller and detach all Springpath controller vnics.
        5. Remove (if needed) and add VM port group "Springpath Controller Management Network" (for eth0 of controller)
        6. Re-attach controller vnic to VM port group "Springpath Controller Management Network"
        7. Remove (if needed) and add a VM port group "Springpath Controller Data Network" (for eth1 of controller)
        8. Re-attach controller vnic to VM port group "Springpath Controller Data Network"
        9. Setup VMKernel port group ("vMotion") and it's IP settings (if needed)
        """
        logging.debug("Configuring networking directly on ESXi.")

        if SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_NOT_SUPPORTED,
                             "Attempting to configure VDS networking from ESXi directly. This is not possible.")

        # create VI service instance for each ESXi instance and sequentially configure, etc.
        for esx_host in SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT:

            logging.debug("Configuring networking on ESXi {0}.".format(esx_host))

            self._initialize_ESXi(esx_host,
                                  SpringpathNetworkingSetup_VCenter.ESX_USER,
                                  SpringpathNetworkingSetup_VCenter.ESX_PWD)

            # Create HX network elements if HX hardware
            if SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY == SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_HX and executing_on_installer():
                self.configureHXSpecificNetworkElements()
            else:
                # check standard switches
                # already exist on all hosts
                # for non-HX hardware
                if not self._hasStandardSwitches():
                    self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                     "Unable to find standard switches on all specified hosts.")

            if SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE == SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE_OPTION_VM_PORT_GROUP:

                self._configureMgmtPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT,
                                               False)

                self._configureDataPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA,
                                               False)

                if hasattr(SpringpathNetworkingSetup_VCenter, 'VSWITCH_CTL_REPL'):
                    self._configureReplicationPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_REPL,
                                                   SpringpathNetworkingSetup_VCenter.PG_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VLANID_CTL_REPL_NWK,
                                                   False)
            else:
                if not SpringpathNetworkingSetup_VCenter.HARD_RESET:
                    self._initializeConfiguredHostControllerPairs_Standard()

                # self._arp_pingValidateDuplicates()
                self._setResetControllers()
                self._configureMgmtPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT,
                                               True)

                # we create the VMKernel data port first
                # since needed, prior to controller data port
                # attachment
                if SpringpathNetworkingSetup_VCenter.CREATE_VMKERNEL_DATA_PORTGROUP:
                    self._configureDataPG_Standard_ESX(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                                       SpringpathNetworkingSetup_VCenter.PG_ESX_DATA,
                                                       SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA)

                self._configureDataPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA,
                                               True)


                if hasattr(SpringpathNetworkingSetup_VCenter, 'VSWITCH_CTL_REPL'):
                    self._configureReplicationPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_REPL,
                                                   SpringpathNetworkingSetup_VCenter.PG_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VLANID_CTL_REPL_NWK,
                                                   True)

                self._resetControllerUDEVRules()
                self._reconfigureVirtualEthernetDevices()

                self._powerOnControllers()
                self._arp_pingControllerGateways()
                self.resetScript()

    def configureNetworkingFromVCenter(self):
        """
        Configures Springpath networking via vCenter by doing the following:
        1. Initialize Access to vCenter
        2. Reset UDEV rules
        3. Reset controller IP settings.
        4. Power down controller and detach all Springpath controller vnics.
        5. Remove (if needed) and add VM port group "Storage Controller Management Network" (for eth0 of controller)
        6. Re-attach controller vnic to VM port group "Storage Controller Management Network"
        7. Remove (if needed) and add a VM port group "Storage Controller Data Network" (for eth1 of controller)
        8. Re-attach controller vnic to VM port group "Storage Controller Data Network"
        9. Setup VMKernel port group ("vMotion") and it's IP settings (if needed)
        """
        logging.debug("Configuring networking directly from vCenter.")

        # create VI service instance, etc.
        if not self._initialize_VCenter(SpringpathNetworkingSetup_VCenter.VCENTER_HOST,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_USER,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_PWD,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER):
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                             "Could not initialize vCenter properly. Check vCenter parameters and that data center exists.")

        if self._setupVDSConfiguration():

            logging.debug("Attempting to configure controller on VDS switches.")

            if SpringpathNetworkingSetup_VCenter.FACTORY_MODE:
                self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                 "Attempting to configure VDS in factory install mode. This is unsupported.")

            if not self._switchExists_VDS(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT):
                self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                 "Unable to find VDS switch {0}.".format(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT))

            if not self._switchExists_VDS(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA):
                self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                 "Unable to find VDS switch {0}.".format(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA))

            if SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE == SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE_OPTION_VM_PORT_GROUP:

                self._configureMgmtPG_VDS(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT,
                                          False)

                self._configureDataPG_VDS(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA,
                                          False)

            else:
                if not SpringpathNetworkingSetup_VCenter.HARD_RESET:
                    self._initializeConfiguredHostControllerPairs_VDS()

                # self._arp_pingValidateDuplicates()
                self._setResetControllers()
                self._configureMgmtPG_VDS(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_MGMT,
                                          SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT,
                                          True)

                # we create the VMKernel data port first
                # since needed, prior to controller data port
                # attachment
                if SpringpathNetworkingSetup_VCenter.CREATE_VMKERNEL_DATA_PORTGROUP:
                    self._configureDataPG_VDS_ESX(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                                  SpringpathNetworkingSetup_VCenter.PG_ESX_DATA,
                                                  SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA)

                self._configureDataPG_VDS(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_DATA,
                                          SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA,
                                          True)

        else:

            # Create HX network elements if HX hardware
            if SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY == SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_HX and executing_on_installer():
                self.configureHXSpecificNetworkElements()
            else:
                # check standard switches
                # already exist on all hosts
                # for non-HX hardware
                if not self._hasStandardSwitches():
                    self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                     "Unable to find standard switches on all specified hosts.")

            if SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE == SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE_OPTION_VM_PORT_GROUP:

                self._configureMgmtPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT,
                                               False)

                self._configureDataPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA,
                                               False)
                if hasattr(SpringpathNetworkingSetup_VCenter, 'VSWITCH_CTL_REPL'):
                    self._configureReplicationPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_REPL,
                                                   SpringpathNetworkingSetup_VCenter.PG_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VLANID_CTL_REPL_NWK,
                                                   False)
            else:
                if not SpringpathNetworkingSetup_VCenter.HARD_RESET:
                    self._initializeConfiguredHostControllerPairs_Standard()

                # self._arp_pingValidateDuplicates()
                self._setResetControllers()
                self._configureMgmtPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_MGMT,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT,
                                               True)

                # we create the VMKernel data port first
                # since needed, prior to controller data port
                # attachment
                if SpringpathNetworkingSetup_VCenter.CREATE_VMKERNEL_DATA_PORTGROUP:

                    # remove hosts from distributed PG
                    # of same name if has same IP. This
                    # allows for seamless migration back
                    # to std. configuration without having
                    # to manually delete VMKernel vnic.
                    self._removeHostsFromDistributedPG(SpringpathNetworkingSetup_VCenter.PG_ESX_DATA, True)
                    self._configureDataPG_Standard_ESX(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                                       SpringpathNetworkingSetup_VCenter.PG_ESX_DATA,
                                                       SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA)

                self._configureDataPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_DATA,
                                               SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA,
                                               True)


                if hasattr(SpringpathNetworkingSetup_VCenter, 'VSWITCH_CTL_REPL'):
                    self._configureReplicationPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_REPL,
                                                   SpringpathNetworkingSetup_VCenter.PG_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_REPL_NWK,
                                                   SpringpathNetworkingSetup_VCenter.VLANID_CTL_REPL_NWK,
                                                   True)
                self._resetControllerUDEVRules()
                self._reconfigureVirtualEthernetDevices()

        if SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE != SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE_OPTION_VM_PORT_GROUP:
            self._powerOnControllers()
            self._arp_pingControllerGateways()
            self.resetScript()

    def configureHXSpecificNetworkElements(self):
        """
        Configures network
        elements specific to HX
        hardware setups.
        """
        self._configureHXSwitches()
        self._configureVMPG_Standard(SpringpathNetworkingSetup_VCenter.VSWITCH_VMNETWORK,
                                     SpringpathNetworkingSetup_VCenter.PG_INFO_LIST_VMNETWORK)

    # Configuration detection methods
    # -------------------------------

    def _setupVDSConfiguration(self):
        """
        Determines if should setup in a VDS
        configuration in vCenter.
        """
        return SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION

    def _hostsFoundInVCenter(self):
        """
        Determines if ESXi hosts are in vCenter or
        not to assess whether to configure via
        vCenter or directly by contacting ESXi.
        If only some ESXi are in vCenter but not
        all, the script errors out.
        """
        logging.debug("Attempting to connect to vCenter and see if hosts already added to it.")

        # make sure we even have vCenter parameters
        if not (SpringpathNetworkingSetup_VCenter.VCENTER_HOST and
                SpringpathNetworkingSetup_VCenter.VCENTER_USER and
                SpringpathNetworkingSetup_VCenter.VCENTER_PWD and
                SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER):
            return False

        if not self._initialize_VCenter(SpringpathNetworkingSetup_VCenter.VCENTER_HOST,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_USER,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_PWD,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER):
            return False

        hosts = self._getHosts()
        self.resetScript()

        if len(hosts) == len(SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST):
            return True
        elif len(hosts) > 0:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_CLUSTER_INVALID_STATE,
                             "Some ESX hosts are in vCenter but some are not. This is an invalid configuration!")
        else:
            return False

    def _hasStandardSwitches(self):
        """
        Determines if we are in a standard
        configuration by checking
        to see if specified switches are std
        switches on every ESXi host we
        are configuring.
        """
        hosts = self._getHosts()

        for host in hosts:

            if not (self._switchExists_Standard(host, SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT) and
                    self._switchExists_Standard(host, SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA)):
                return False

        return True

    def _switchExists_Standard(self, host, switch_name):
        """
        Determines if standard switch of
        given name exists on host.
        """

        # validate vswitch exists
        if not [vswitch for vswitch in host.config.network.vswitch if vswitch.name == switch_name]:

            logging.debug("Unable to find valid standard vSwitch {0} on host: {1}.".format(switch_name, host.name))
            return False

        else:
            return True

    def _pnicExists(self, host, nic_name):
        """
        Determines if pNic on a given host exists or not
        """
        if not [phyNic for phyNic in host.config.network.pnic if phyNic.device == nic_name]:
            return False

        else:
            return True

    def _switchExists_VDS(self, switch_name):
        """
        Determines if VDS switch of
        given name exists in datacenter.
        """

        if self._getDistributedVirtualSwitch(switch_name):
            return True
        else:
            return False

    # Initialize Methods
    # -------------------

    def initializeHardwareTypeInventory(self):
        """
        This method goes through all the hosts
        and determines their type (HX vs. NON-HX). From
        this it sets the "HARDWARE_TYPE_INVENTORY" field.
        """
        hasHXHardware = False
        hasNonHXHardware = False

        for esx_host in SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST:

            # We only support creation of
            # new vSwitches HX-based
            # hardware in tunefile
            if isHXHardware(esx_host, SpringpathNetworkingSetup_VCenter.ESX_USER, SpringpathNetworkingSetup_VCenter.ESX_PWD):
                hasHXHardware = True
            else:
                hasNonHXHardware = True

        if hasHXHardware and hasNonHXHardware:
            logging.debug("Detected hardware type inventory to be MIXED (HX and non-HX")
            SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY = SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_MIXED
        elif hasHXHardware:
            logging.debug("Detected hardware type inventory to be HX")
            SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY = SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_HX
        elif hasNonHXHardware:
            logging.debug("Detected hardware type inventory to be non-HX")
            SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY = SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_NON_HX
        else:
            logging.debug("Detected hardware type inventory to be unknown")
            SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY = SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_UNKNOWN

    def _initialize_VCenter(self, vc_host, vc_user, vc_pwd, vc_datacenter_name):
        """
        Initializes script to execute on vCenter.
        """
        logging.debug("Initializing handle to vCenter host: {0}, user: {1}.".format(vc_host, vc_user))

        self.resetScript()
        self.si = connect.SmartConnect(host=self._getHostByName(vc_host), user=vc_user, pwd=vc_pwd)
        self.datacenter = self._getDataCenter(vc_datacenter_name)

        if self.datacenter:
            logging.debug("Discovered datacenter: {0}".format(vc_datacenter_name))
            return True
        else:
            logging.error("Unable to find datacenter: {0} in VC: {1}".format(vc_datacenter_name, vc_host))
            return False

    def _initialize_ESXi(self, esx_host, esx_user, esx_pwd):
        """
        Initializes script to execute on ESXi.
        """
        logging.debug("Initializing handle to ESXi host {0} with user {1}.".format(esx_host, esx_user))

        self.resetScript()
        self.si = connect.SmartConnect(host=self._getHostByName(esx_host), user=esx_user, pwd=esx_pwd)
        self.datacenter = self._getESXiDataCenter()

        if self.datacenter:
            logging.debug("Discovered ESXi datacenter")
        else:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                             "Unable to find ESXi datacenter")

    # Command Line and JSON Parsing Methods
    # -------------------------------------

    def _getFileHandle(self, file_name, required=True):

        if not os.path.isfile(file_name):
            if required:
                self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INTERNAL_ERROR,
                                 "Cannot open the following file since it does not exist: {0}".format(file_name))
            else:
                return None

        return open(file_name)

    def _getBooleanArg(self, strArg):
        """
        Converts command line arg to a boolean.
        """
        if type(strArg) is bool:
            return strArg
        else:
            return strArg.upper() == "TRUE"

    def _getIntArg(self, strArg):
        """
        Converts command line arg to an integer.
        """
        try:
            return int(strArg)
        except ValueError:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INTERNAL_ERROR,
                             "The following argument is invalid since not an integer: {0}".format(strArg))

    def _getArgs(self, arg_names):
        """
        Helps parse command line args into a scalar value.
        """
        cmd_args = sys.argv[1:]
        return_args = {}
        for index, arg in enumerate(cmd_args):
            if arg in arg_names and len(cmd_args) > index + 1:

                if cmd_args[index + 1] and len(cmd_args[index + 1]) > 0 and not cmd_args[index + 1].startswith("--"):
                    return_args[arg] = cmd_args[index + 1]

        return return_args

    def _getArgsLists(self, arg_names):
        """
        Helps parse command line args into a list.
        """
        cmd_args = sys.argv[1:]
        return_args = {}
        for index, arg in enumerate(cmd_args):
            if arg in arg_names:

                arg_val = []
                i = 1
                while len(cmd_args) > index + i and cmd_args[index + i] and len(cmd_args[index + 1]) > 0 and not cmd_args[index + i].startswith("--"):
                    arg_val.append(cmd_args[index + i])
                    i += 1

                return_args[arg] = arg_val

        return return_args

    def _hasArgs(self, arg_names):
        """
        Sets args to True/False depending on if present.
        """
        cmd_args = sys.argv[1:]
        return_args = {}
        for index, arg in enumerate(cmd_args):
            if arg in arg_names:
                return_args[arg] = True

        return return_args

    def _parseCmdLineArgs(self):
        """
        Parses needed command line args.
        """

        logging.debug("Parsing command-line arguments.")

        args = self._getArgs(["--json-config-file", "--json-config-file-networking", "--json-config-file-vcenter", "--configure-mode"])

        if "--json-config-file-networking" in args:
            SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_NETWORKING = args["--json-config-file-networking"]
        if "--json-config-file-vcenter" in args:
            SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_VCENTER = args["--json-config-file-vcenter"]
        if "--json-config-file" in args:
            SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE = args["--json-config-file"]
        if "--configure-mode" in args:
            SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE = args["--configure-mode"]

        if SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_NETWORKING:
            self._parseJSONFileNetworking()

            if SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_VCENTER:
                self._parseJSONFileVCenter()

        elif SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE:
            self._parseJSONFile()
        else:
            self._parseCmdLineArgsForParameters()

    def _parseVswitchInfoFromTunes(self):
        try:
            if SpringpathNetworkingSetup_VCenter.EXTERNAL_STORAGE_ENABLED:
                self.VSWITCH_INFO.update({"vswitch_iscsi": {}})

            for section in self.VSWITCH_INFO:
                self.VSWITCH_INFO[section]['vswitch'] = parseEnvVariableTunes(section + "." + "vswitch")
                self.VSWITCH_INFO[section]['mtu'] = parseEnvVariableTunes(section + "." + "mtu")
                self.VSWITCH_INFO[section]['nic_ordering_policy'] = parseEnvVariableTunes(section + "." + "nic_ordering_policy")
                self.VSWITCH_INFO[section]['load_balancing_policy'] = parseEnvVariableTunes(section + "." + "load_balancing_policy")
                self.VSWITCH_INFO[section]['notify_switches'] = parseEnvVariableTunes(section + "." + "notify_switches")

            for section in self.VSWITCH_INFO:
                for key in self.VSWITCH_INFO[section]:
                    logging.debug("vSwitch: {}, key: {}, value: {}".format(section, key, self.VSWITCH_INFO[section][key]))
        except:
            ex = sys.exc_info()
            logging.exception("Exception occurred parsing switch information from tunes file. Class: {}, message: {}.".format(ex[0], ex[1]))
            raise

    def _getVswitchInfo(self, host):
        """
        Method to iterate over pnics, sort them as per pci order and populate VSWITCH_INFO pnics
        Args:
            host: vim.HostSystem object
        Returns:
            Nothing, populates dictionary VSWITCH_INFO pnic info
        Raises:
            Generic exception
        """
        try:
            vswitch_info = getVmnicInfo(host, SpringpathNetworkingSetup_VCenter.EXTERNAL_STORAGE_ENABLED)
            for section in self.VSWITCH_INFO:
                self.VSWITCH_INFO[section]['pnic_a'] = vswitch_info[section]['pnic_a']
                self.VSWITCH_INFO[section]['pnic_b'] = vswitch_info[section]['pnic_b']
        except:
            ex = sys.exc_info()
            logging.exception("Exception occurred getting vmnics information from host. Class: {}, \
            message: {}.".format(ex[0], ex[1]))
            raise

    def _setTuneBasedVariables(self):
        """
        Parses Tunes file containing environment variables
        used for deployment.
        """
        pg_ctl_mgmt = parseEnvVariableTunes("networking.portgroup_controller_mgmt")
        if pg_ctl_mgmt:
            SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT = pg_ctl_mgmt

        pg_ctl_data = parseEnvVariableTunes("networking.portgroup_controller_data")
        if pg_ctl_data:
            SpringpathNetworkingSetup_VCenter.PG_CTL_DATA = pg_ctl_data

        pg_esx_data = parseEnvVariableTunes("networking.portgroup_hypervisor_data")
        if pg_esx_data:
            SpringpathNetworkingSetup_VCenter.PG_ESX_DATA = pg_esx_data

        pg_esx_vmotion = parseEnvVariableTunes("networking.portgroup_hypervisor_vmotion")
        if pg_esx_vmotion:
            SpringpathNetworkingSetup_VCenter.PG_ESX_VMOTION = pg_esx_vmotion

        mtu_vmotion = parseEnvVariableTunes("networking.mtu_vmotion")
        if mtu_vmotion:
            logging.debug("Got mtu size for vmotion network of {} from tunes file.".format(mtu_vmotion))
            try:
                SpringpathNetworkingSetup_VCenter.MTU_VMOTION = int(mtu_vmotion)
            except:
                logging.debug("Error parsing vmotion mtu size from string: {}".format(mtu_vmotion))
                raise

        mtu_data = parseEnvVariableTunes("networking.mtu_data")
        if mtu_data:
            logging.debug("Got mtu size for data network of {} from tunes file.".format(mtu_data))
            try:
                SpringpathNetworkingSetup_VCenter.MTU_DATA = int(mtu_data)
            except:
                logging.debug("Error parsing data mtu size from string: {}".format(mtu_data))
                raise

    def _parseJSONFileVCenter(self):
        """
        Parses vCenter JSON file for deployment
        appliance.
        """
        logging.debug("Parsing JSON file {0} for VCENTER input parameters.".format(SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_VCENTER))

        json_handle = self._getFileHandle(SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_VCENTER)
        json_data = json.load(json_handle)

        SpringpathNetworkingSetup_VCenter.VCENTER_HOST = self._getVCenterHostFromVCenterURL(json_data['vCenterUrl'])
        SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER = json_data['vCenterDatacenter']['id']
        SpringpathNetworkingSetup_VCenter.VCENTER_CLUSTER = json_data['vCenterCluster']['id']
        SpringpathNetworkingSetup_VCenter.VCENTER_USER = json_data['vCenterUserName']
        SpringpathNetworkingSetup_VCenter.VCENTER_PWD = base64.b64decode(json_data['vCenterPassword'])

        if 'esxUserName' in json_data:
            SpringpathNetworkingSetup_VCenter.ESX_USER = json_data['esxUserName'].strip()
        if 'esxPassword' in json_data:
            SpringpathNetworkingSetup_VCenter.ESX_PWD = base64.b64decode(json_data['esxPassword']).strip()
        if 'ctlvmPassword' in json_data:
            SpringpathNetworkingSetup_VCenter.USER_CTL_PWD = base64.b64decode(json_data['ctlvmPassword']).strip()

        if 'nodes' in json_data:
            for ipAddress in json_data['nodes']:
                if 'role' in json_data['nodes'][ipAddress]:
                    SpringpathNetworkingSetup_VCenter.ESX_ROLE_MAP[self._getHostByName(ipAddress)] = json_data['nodes'][ipAddress]['role']

        if 'factoryMode' in json_data:
            # Thrift XDR encoding of boolean value will get translated into 0/1 integer data
            SpringpathNetworkingSetup_VCenter.FACTORY_MODE = self._getIntArg(json_data['factoryMode'])
            # Convert this integer flag to boolean to be consistent everywhere else
            if SpringpathNetworkingSetup_VCenter.FACTORY_MODE == 1:
                SpringpathNetworkingSetup_VCenter.FACTORY_MODE = True
                logging.debug("ParseJSONFileVcenter: Factory mode is set")
            else:
                SpringpathNetworkingSetup_VCenter.FACTORY_MODE = False
                logging.debug("ParseJSONFileVcenter: Factory mode is not set")

        json_handle.close()

    def _getVCenterHostFromVCenterURL(self, url):
        try:
            p = urlparse.urlparse(url)
            if p.netloc:
                return p.hostname
            elif p.scheme and not p.netloc:
                return self._getVCenterHostFromVCenterURL('//%s' % url)
            elif p.path:
                return self._getVCenterHostFromVCenterURL('//%s' % p.path)
            else:
                return url
        except Exception:
            logging.debug(traceback.format_exc())
            return url

    def _parseJSONFileNetworking(self):
        """
        Parses networking JSON file for deployment
        appliance.
        """
        logging.debug("Parsing JSON file {0} for NETWORKING input parameters.".format(SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_NETWORKING))
        json_handle = self._getFileHandle(SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_NETWORKING)
        json_data = json.load(json_handle)

        # fetch NTP, DNS related parameters
        # ---------------------------------

        SpringpathNetworkingSetup_VCenter.NTP_HOST_LIST = []
        SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST = []
        SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST = []

        if 'dnsServers' in json_data:
            for dnsServer in json_data['dnsServers']:
                SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST.append(dnsServer)

        if 'ntpServers' in json_data:
            for ntpServer in json_data['ntpServers']:
                SpringpathNetworkingSetup_VCenter.NTP_HOST_LIST.append(ntpServer)

        if 'dnsSearch' in json_data:
            for dnsSearch in json_data['dnsSearch']:
                SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST.append(dnsSearch)

        # fetch network related parameters
        # --------------------------------

        # parse information for Management network

        if 'vNetworkMgmt' in json_data and len(json_data['vNetworkMgmt']['vSwitch']) > 0:
            SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT = json_data['vNetworkMgmt']['vSwitch']

            if 'pNic' in json_data['vNetworkMgmt']:
                SpringpathNetworkingSetup_VCenter.PNIC_CTL_MGMT = json_data['vNetworkMgmt']['pNic']

            # we have a single global isVDS flag which
            # we fetch on both mgmt or data network
            # (whichever has it, we assume same value for now).
            if 'isVDSConfiguration' in json_data['vNetworkMgmt']:
                SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION = json_data['vNetworkMgmt']['isVDSConfiguration']
        else:
            # we will attempt to get vSwitch, etc. info. from existing cluster when not specified
            SpringpathNetworkingSetup_VCenter.CONFIG_PARAMS_FROM_EXISTING_CLUSTER = True

        # parse information for Data network

        if 'vNetworkData' in json_data and len(json_data['vNetworkData']['vSwitch']) > 0:
            SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA = json_data['vNetworkData']['vSwitch']

            if 'pNic' in json_data['vNetworkData']:
                SpringpathNetworkingSetup_VCenter.PNIC_CTL_DATA = json_data['vNetworkData']['pNic']

            # we have a single global isVDS flag which
            # we fetch on both mgmt or data network
            # (whichever has it, we assume same value for now).
            if 'isVDSConfiguration' in json_data['vNetworkData']:
                SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION = json_data['vNetworkData']['isVDSConfiguration']
        else:
            # we will attempt to get vSwitch, etc. info. from existing cluster when not specified
            SpringpathNetworkingSetup_VCenter.CONFIG_PARAMS_FROM_EXISTING_CLUSTER = True

        # parse information for VMotion network

        if 'vNetworkVMotion' in json_data and 'vlanId' in json_data['vNetworkVMotion']:
            SpringpathNetworkingSetup_VCenter.VLANID_VMOTION = json_data['vNetworkVMotion']['vlanId']

        # parse information for VM network

        if 'vNetworkVM' in json_data and \
                'portGroupSettings' in json_data['vNetworkVM'] and \
                len(json_data['vNetworkVM']['portGroupSettings']) > 0:

            for port_group_settings in json_data['vNetworkVM']['portGroupSettings']:

                pg_name = port_group_settings['name']
                vlanId = port_group_settings['vlanId'] if port_group_settings['vlanId'] else 0
                SpringpathNetworkingSetup_VCenter.PG_INFO_LIST_VMNETWORK.append({"pg_name": pg_name, "vlanid": vlanId})

        # parse information for iscsi network
        if 'vNetworkiSCSI' in json_data and \
                'portGroupSettings' in json_data['vNetworkiSCSI'] and \
                len(json_data['vNetworkiSCSI']['portGroupSettings']) > 0:

            SpringpathNetworkingSetup_VCenter.EXTERNAL_STORAGE_ENABLED = True
            for port_group_settings in json_data['vNetworkiSCSI']['portGroupSettings']:

                pg_name = port_group_settings['name']
                vlanId = port_group_settings['vlanId'] if port_group_settings['vlanId'] else 0
                SpringpathNetworkingSetup_VCenter.PG_INFO_LIST_ISCSINETWORK.append({"pg_name": pg_name, "vlanid": vlanId})


        # fetch IP related parameters
        # ---------------------------

        SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST = []
        SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT = []
        SpringpathNetworkingSetup_VCenter.IP_CTL_DATA = []
        SpringpathNetworkingSetup_VCenter.IP_ESX_DATA = []

        if 'nodeIPSettings' in json_data:

            for ipAddress in json_data['nodeIPSettings']:

                SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST.append(ipAddress)

                for ipSettings in json_data['nodeIPSettings'][ipAddress]:

                    if ipSettings['method'] == 1:  # DHCP

                        if ipSettings['stService'] == 1:  # controller-data
                            SpringpathNetworkingSetup_VCenter.IP_CTL_DATA.append('')
                            self._setDataPortArgs(ipSettings)

                        elif ipSettings['stService'] == 7:  # vMotion
                            SpringpathNetworkingSetup_VCenter.IP_ESX_DATA.append('')
                            self._setDataPortArgs(ipSettings)

                        elif ipSettings['stService'] == 3:  # hypervisor - this is never DHCP
                            SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT.append(ipSettings['addr'])
                            self._setMgmtPortArgs(ipSettings)

                        elif ipSettings['stService'] == 8:  # controller-mgmt
                            SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT.append('')
                            self._setMgmtPortArgs(ipSettings)

                        elif ipSettings['stService'] == 5:  # mgmt
                            self._setMgmtPortArgs(ipSettings)

                    elif ipSettings['method'] == 2:  # static

                        if ipSettings['stService'] == 1:  # controller-data
                            SpringpathNetworkingSetup_VCenter.IP_CTL_DATA.append(ipSettings['addr'])
                            self._setDataPortArgs(ipSettings)

                        elif ipSettings['stService'] == 7:  # vMotion
                            SpringpathNetworkingSetup_VCenter.IP_ESX_DATA.append(ipSettings['addr'])
                            self._setDataPortArgs(ipSettings)

                        elif ipSettings['stService'] == 3:  # hypervisor
                            SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT.append(ipSettings['addr'])
                            self._setMgmtPortArgs(ipSettings)

                        elif ipSettings['stService'] == 8:  # controller-mgmt
                            SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT.append(ipSettings['addr'])
                            self._setMgmtPortArgs(ipSettings)

                        elif ipSettings['stService'] == 5:  # mgmt
                            self._setMgmtPortArgs(ipSettings)

        json_handle.close()

    def _setMgmtPortArgs(self, ipSettings):

        if not SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_MGMT:
            if ipSettings['subnetMask']:
                SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_MGMT = ipSettings['subnetMask']

        if not SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT:
            if 'gateway' in ipSettings and ipSettings['gateway']:
                SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT = ipSettings['gateway']

        if not SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT:
            if 'vlanId' in ipSettings and ipSettings['vlanId']:
                SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT = self._getIntArg(ipSettings['vlanId'])

    def _setDataPortArgs(self, ipSettings):

        if not SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA:
            if ipSettings['subnetMask']:
                SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA = ipSettings['subnetMask']

        if not SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA:
            if 'gateway' in ipSettings and ipSettings['gateway']:
                SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA = ipSettings['gateway']

        if not SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA:
            if 'vlanId' in ipSettings and ipSettings['vlanId']:
                SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA = self._getIntArg(ipSettings['vlanId'])

    def _parseJSONFile(self):
        """
        Parses end-user JSON file.
        """
        logging.debug("Parsing JSON file {0} for input parameters.".format(SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE))

        # get remaining parameters from JSON
        # ------------------------------------------------

        json_handle = self._getFileHandle(SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE)
        json_data = json.load(json_handle)

        if 'vCenter' in json_data:
            if 'url' in json_data['vCenter']:
                SpringpathNetworkingSetup_VCenter.VCENTER_HOST = self._getVCenterHostFromVCenterURL(json_data['vCenter']['url'])
            if 'datacenter' in json_data['vCenter']:
                SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER = json_data['vCenter']['datacenter']
            if 'clustername' in json_data['vCenter'] and 'expandCluster' in json_data:
                SpringpathNetworkingSetup_VCenter.VCENTER_CLUSTER = json_data['vCenter']['clustername']
                SpringpathNetworkingSetup_VCenter.CONFIG_PARAMS_FROM_EXISTING_CLUSTER = True
            if 'vCenterUserName' in json_data['vCenter']:
                SpringpathNetworkingSetup_VCenter.VCENTER_USER = json_data['vCenter']['vCenterUserName']
            if 'vCenterPassword' in json_data['vCenter']:
                SpringpathNetworkingSetup_VCenter.VCENTER_PWD = base64.b64decode(json_data['vCenter']['vCenterPassword']).strip()
            if 'esxUserName' in json_data['vCenter']:
                SpringpathNetworkingSetup_VCenter.ESX_USER = json_data['vCenter']['esxUserName']
            if 'esxPassword' in json_data['vCenter']:
                SpringpathNetworkingSetup_VCenter.ESX_PWD = base64.b64decode(json_data['vCenter']['esxPassword']).strip()
            if 'factoryMode' in json_data['vCenter']:
                #
                # Here factoryMode is set in JSON as a boolean string (True/False)
                SpringpathNetworkingSetup_VCenter.FACTORY_MODE = self._getBooleanArg(json_data['vCenter']['factoryMode'])
                if SpringpathNetworkingSetup_VCenter.FACTORY_MODE:
                    logging.debug("ParseJSONFile: Factory mode is set")
                else:
                    logging.debug("ParseJSONFile: Factory mode is not set")

        if 'vSwitch' in json_data:
            if 'hypervisorAndipmi' in json_data['vSwitch'] and len(json_data['vSwitch']['hypervisorAndipmi']) > 0:
                SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT = json_data['vSwitch']['hypervisorAndipmi']
            if 'controllerAndvMotion' in json_data['vSwitch'] and len(json_data['vSwitch']['controllerAndvMotion']) > 0:
                SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA = json_data['vSwitch']['controllerAndvMotion']

        if 'pNic' in json_data:
            if 'hypervisorAndipmi' in json_data['pNic'] and len(json_data['pNic']['hypervisorAndipmi']) > 0:
                SpringpathNetworkingSetup_VCenter.PNIC_CTL_MGMT = json_data['pNic']['hypervisorAndipmi']
            if 'controllerAndvMotion' in json_data['pNic'] and len(json_data['pNic']['controllerAndvMotion']) > 0:
                SpringpathNetworkingSetup_VCenter.PNIC_CTL_DATA = json_data['pNic']['controllerAndvMotion']

        if 'vlan' in json_data:
            if 'hypervisorAndipmi' in json_data['vlan']:
                SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT = self._getIntArg(json_data['vlan']['hypervisorAndipmi'])
            if 'controllerAndvMotion' in json_data['vlan']:
                SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA = self._getIntArg(json_data['vlan']['controllerAndvMotion'])
            if 'vMotion' in json_data['vlan']:
                SpringpathNetworkingSetup_VCenter.VLANID_VMOTION = self._getIntArg(json_data['vlan']['vMotion'])
            if 'vmNetwork' in json_data['vlan']:
                for vlan_vmnetwork_info in json_data['vlan']['vmNetwork']:
                    SpringpathNetworkingSetup_VCenter.PG_INFO_LIST_VMNETWORK.append({'pg_name': vlan_vmnetwork_info['name'], 'vlanid': vlan_vmnetwork_info['vlanid']})
            if 'iscsiNetwork' in json_data['vlan']:
                for vlan_iscsinetwork_info in json_data['vlan']['iscsiNetwork']:
                    SpringpathNetworkingSetup_VCenter.PG_INFO_LIST_ISCSINETWORK.append({'pg_name': vlan_iscsinetwork_info['name'], 'vlanid': vlan_iscsinetwork_info['vlanid']})

        if 'subnetMask' in json_data:
            if 'hypervisorAndipmi' in json_data['subnetMask']:
                SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_MGMT = json_data['subnetMask']['hypervisorAndipmi']
            if 'controllerAndvMotion' in json_data['subnetMask']:
                SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA = json_data['subnetMask']['controllerAndvMotion']

        if 'gateway' in json_data:
            if 'hypervisorAndipmi' in json_data['gateway']:
                SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT = json_data['gateway']['hypervisorAndipmi']
            if 'controllerAndvMotion' in json_data['gateway']:
                SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA = json_data['gateway']['controllerAndvMotion']

        if 'vds_configuration' in json_data:
            SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION = self._getBooleanArg(json_data['vds_configuration'])

        if 'force_move_vm_port_group' in json_data:
            SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VM_PORTGROUP = self._getBooleanArg(json_data['force_move_vm_port_group'])

        if 'force_move_vmkernel_port_group' in json_data:
            SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VMKERNEL_PORTGROUP = self._getBooleanArg(json_data['force_move_vmkernel_port_group'])

        if 'hard_reset' in json_data:
            SpringpathNetworkingSetup_VCenter.HARD_RESET = self._getBooleanArg(json_data['hard_reset'])

        if 'create_vmkernel_data_port_group' in json_data:
            SpringpathNetworkingSetup_VCenter.CREATE_VMKERNEL_DATA_PORTGROUP = self._getBooleanArg(json_data['create_vmkernel_data_port_group'])

        if 'dnsServers' in json_data and len(json_data['dnsServers']) > 0:
            SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST = json_data['dnsServers']

        if 'dnsSearch' in json_data and len(json_data['dnsSearch']) > 0:
            SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST = json_data['dnsSearch']

        SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST = []
        SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT = []
        SpringpathNetworkingSetup_VCenter.IP_CTL_DATA = []
        SpringpathNetworkingSetup_VCenter.IP_ESX_DATA = []
        SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT = []

        if 'ipAddresses' in json_data:
            for ipAddress in json_data['ipAddresses']:

                if 'controller_mgmt' in ipAddress:
                    SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT.append(ipAddress['controller_mgmt'])
                elif 'management' in ipAddress:  # backward compatibility
                    SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT.append(ipAddress['management'])
                else:
                    SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT.append('')  # DHCP

                if 'controller_data' in ipAddress:
                    SpringpathNetworkingSetup_VCenter.IP_CTL_DATA.append(ipAddress['controller_data'])
                elif 'controller' in ipAddress:  # backward compatibility
                    SpringpathNetworkingSetup_VCenter.IP_CTL_DATA.append(ipAddress['controller'])
                else:
                    SpringpathNetworkingSetup_VCenter.IP_CTL_DATA.append('')  # DHCP

                if 'hypervisor_data' in ipAddress:
                    SpringpathNetworkingSetup_VCenter.IP_ESX_DATA.append(ipAddress['hypervisor_data'])
                elif 'vMotion' in ipAddress:  # backward compatibility
                    SpringpathNetworkingSetup_VCenter.IP_ESX_DATA.append(ipAddress['vMotion'])
                elif 'dataNetwork' in ipAddress:  # backward compatibility
                    SpringpathNetworkingSetup_VCenter.IP_ESX_DATA.append(ipAddress['dataNetwork'])
                else:
                    SpringpathNetworkingSetup_VCenter.IP_ESX_DATA.append('')  # DHCP

                if 'hypervisor_mgmt' in ipAddress:
                    SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT.append(ipAddress['hypervisor_mgmt'])
                    SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST.append(ipAddress['hypervisor_mgmt'])
                elif 'hypervisor' in ipAddress:  # backward compatibility
                    SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT.append(ipAddress['hypervisor'])
                    SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST.append(ipAddress['hypervisor'])
                else:
                    self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                     "Error parsing JSON file. ESX management address not specified for host entry.")

        json_handle.close()

        # we still get vCenter and ESXi user/pwd from command-line to override JSON file
        # ------------------------------------------------------------------------------
        args = self._getArgs(["--vcenter-user",
                              "--vcenter-password",
                              "--esx-user",
                              "--esx-password"])

        if "--vcenter-user" in args:
            SpringpathNetworkingSetup_VCenter.VCENTER_USER = args["--vcenter-user"]

        if "--vcenter-password" in args:
            SpringpathNetworkingSetup_VCenter.VCENTER_PWD = args["--vcenter-password"]

        if "--esx-user" in args:
            SpringpathNetworkingSetup_VCenter.ESX_USER = args["--esx-user"]

        if "--esx-password" in args:
            SpringpathNetworkingSetup_VCenter.ESX_PWD = args["--esx-password"]

    def _parseCmdLineArgsForParameters(self):
        """
        Parses additional arguments from command line.
        """
        logging.debug("Parsing command-line arguments for all input parameters.")

        args = self._getArgs(["--esx-user",
                              "--esx-password",
                              "--ctl-user",
                              "--ctl-password",
                              "--vlanid-mgmt",
                              "--vlanid-data",
                              "--vswitch-mgmt",
                              "--vswitch-data",
                              "--vswitch-repl",
                              "--vcenter-host",
                              "--vcenter-datacenter",
                              "--vcenter-cluster",
                              "--vcenter-user",
                              "--vcenter-password",
                              "--netmask-mgmt",
                              "--netmask-data",
                              "--gateway-mgmt",
                              "--gateway-data",
                              "--force-move-vm-portgroup",
                              "--force-move-vmkernel-portgroup",
                              "--hard-reset",
                              "--create-vmkernel-data-pg",
                              "--vds-configuration"])

        if "--vcenter-host" in args:
            SpringpathNetworkingSetup_VCenter.VCENTER_HOST = args["--vcenter-host"]
        if "--vcenter-datacenter" in args:
            SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER = args["--vcenter-datacenter"]
        if "--vcenter-cluster" in args:
            SpringpathNetworkingSetup_VCenter.VCENTER_CLUSTER = args["--vcenter-cluster"]
        if "--vcenter-user" in args:
            SpringpathNetworkingSetup_VCenter.VCENTER_USER = args["--vcenter-user"]
        if "--vcenter-password" in args:
            SpringpathNetworkingSetup_VCenter.VCENTER_PWD = args["--vcenter-password"]
        if "--esx-user" in args:
            SpringpathNetworkingSetup_VCenter.ESX_USER = args["--esx-user"]
        if "--esx-password" in args:
            SpringpathNetworkingSetup_VCenter.ESX_PWD = args["--esx-password"]
        if "--ctl-user" in args:
            SpringpathNetworkingSetup_VCenter.CTL_USER = args["--ctl-user"]
        if "--ctl-password" in args:
            SpringpathNetworkingSetup_VCenter.CTL_PWD = args["--ctl-password"]
            SpringpathNetworkingSetup_VCenter.USER_CTL_PWD = args["--ctl-password"]
        if "--vlanid-mgmt" in args:
            SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT = self._getIntArg(args["--vlanid-mgmt"])
        if "--vlanid-data" in args:
            SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA = self._getIntArg(args["--vlanid-data"])
        if "--vswitch-mgmt" in args:
            SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT = args["--vswitch-mgmt"]
        if "--vswitch-repl" in args:
            SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_REPL = args["--vswitch-repl"]
        # else:
        #     SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_REPL = SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT
        if "--vswitch-data" in args:
            SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA = args["--vswitch-data"]
        if "--pnic-mgmt" in args:
            SpringpathNetworkingSetup_VCenter.PNIC_CTL_MGMT = args["--pnic-mgmt"]
        if "--pnic-data" in args:
            SpringpathNetworkingSetup_VCenter.PNIC_CTL_DATA = args["--pnic-data"]
        if "--netmask-mgmt" in args:
            SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_MGMT = args["--netmask-mgmt"]
        if "--netmask-data" in args:
            SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA = args["--netmask-data"]
        if "--gateway-mgmt" in args:
            SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT = args["--gateway-mgmt"]
        if "--gateway-data" in args:
            SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA = args["--gateway-data"]
        if "--force-move-vm-portgroup" in args:
            SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VM_PORTGROUP = self._getBooleanArg(args["--force-move-vm-portgroup"])
        if "--force-move-vmkernel-portgroup" in args:
            SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VMKERNEL_PORTGROUP = self._getBooleanArg(args["--force-move-vmkernel-portgroup"])
        if "--hard-reset" in args:
            SpringpathNetworkingSetup_VCenter.HARD_RESET = self._getBooleanArg(args["--hard-reset"])
        if "--create-vmkernel-data-pg" in args:
            SpringpathNetworkingSetup_VCenter.CREATE_VMKERNEL_DATA_PORTGROUP = self._getBooleanArg(args["--create-vmkernel-data-pg"])
        if "--vds-configuration" in args:
            SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION = self._getBooleanArg(args["--vds-configuration"])

        args = self._getArgsLists(["--esx-host-list",
                                   "--ip-ctl-mgmt-list",
                                   "--ip-ctl-data-list",
                                   "--ip-esx-data-list",
                                   "--dns-host-list",
                                   "--dns-search-list"])

        if "--esx-host-list" in args:
            SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST = args["--esx-host-list"]
            SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT = args["--esx-host-list"]
        if "--ip-ctl-mgmt-list" in args:
            SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT = args["--ip-ctl-mgmt-list"]
        if "--ip-ctl-data-list" in args:
            SpringpathNetworkingSetup_VCenter.IP_CTL_DATA = args["--ip-ctl-data-list"]
        if "--ip-esx-data-list" in args:
            SpringpathNetworkingSetup_VCenter.IP_ESX_DATA = args["--ip-esx-data-list"]
        if "--dns-host-list" in args:
            SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST = args["--dns-host-list"]
        if "--dns-search-list" in args:
            SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST = args["--dns-search-list"]

    def _validateAndPrintParameters(self):

        logging.debug("Configuring with the following parameters:\n"
                      "--vcenter-host --> {0}\n"
                      "--vcenter-datacenter --> {1}\n"
                      "--vcenter-cluster --> {2}\n"
                      "--vcenter-user --> {3}\n"
                      "--vcenter-password --> {4}\n"
                      "--esx-user --> {5}\n"
                      "--esx-password --> {6}\n"
                      "--ctl-user --> {7}\n"
                      "--ctl-password --> {8}\n"
                      "--force-move-vm-portgroup --> {9}\n"
                      "--force-move-vmkernel-portgroup --> {10}\n"
                      "--hard-reset --> {11}\n"
                      "--create-vmkernel-data-pg --> {12}\n"
                      "--vds-configuration --> {13}\n"
                      "--esx-host-list --> {14}\n"
                      "--dns-host-list --> {15}\n"
                      "--dns-search-list --> {16}\n"
                      "--vswitch-mgmt --> {17}\n"
                      "--pnic-mgmt --> {18}\n"
                      "--pg-mgmt --> {19}\n"
                      "--vlanid-mgmt --> {20}\n"
                      "--ip-esx-mgmt --> {21}\n"
                      "--ip-ctl-mgmt-list --> {22}\n"
                      "--netmask-mgmt --> {23}\n"
                      "--gateway-mgmt --> {24}\n"
                      "--vswitch-data --> {25}\n"
                      "--pnic-data --> {26}\n"
                      "--pg-data --> {27}\n"
                      "--vlanid-data --> {28}\n"
                      "--ip-esx-data-list --> {29}\n"
                      "--ip-ctl-data-list --> {30}\n"
                      "--netmask-data --> {31}\n"
                      "--gateway-data --> {32}\n"
                      "--json-config-file --> {33}\n"
                      "--json-config-file-vcenter --> {34}\n"
                      "--json-config-file-networking --> {35}\n"
                      "--configure-mode --> {36}\n"
                      .format(SpringpathNetworkingSetup_VCenter.VCENTER_HOST,
                              SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER,
                              SpringpathNetworkingSetup_VCenter.VCENTER_CLUSTER,
                              SpringpathNetworkingSetup_VCenter.VCENTER_USER,
                              '**********',
                              SpringpathNetworkingSetup_VCenter.ESX_USER,
                              '**********',
                              SpringpathNetworkingSetup_VCenter.CTL_USER,
                              '**********',
                              SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VM_PORTGROUP,
                              SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VMKERNEL_PORTGROUP,
                              SpringpathNetworkingSetup_VCenter.HARD_RESET,
                              SpringpathNetworkingSetup_VCenter.CREATE_VMKERNEL_DATA_PORTGROUP,
                              SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION,
                              SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST,
                              SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                              SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST,
                              SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                              SpringpathNetworkingSetup_VCenter.PNIC_CTL_MGMT,
                              SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                              SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT,
                              SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT,
                              SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT,
                              SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_MGMT,
                              SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT,
                              SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                              SpringpathNetworkingSetup_VCenter.PNIC_CTL_DATA,
                              SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                              SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA,
                              SpringpathNetworkingSetup_VCenter.IP_ESX_DATA,
                              SpringpathNetworkingSetup_VCenter.IP_CTL_DATA,
                              SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA,
                              SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA,
                              SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE,
                              SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_VCENTER,
                              SpringpathNetworkingSetup_VCenter.JSON_CONFIG_FILE_NETWORKING,
                              SpringpathNetworkingSetup_VCenter.CONFIGURE_MODE))

        # TODO - Complete validation step here...
        if not SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST or \
                len(SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST) == 0:
            self.usage()
            sys.exit(1)

    # Utility methods
    # ---------------

    def _enableLogging(self, console_logging=False, syslog_logging=False):
        """
        Turns on logging.
        """

        # only capture warnings
        # on installer. Does not
        # work on ESXi
        if executing_on_installer():
            logging.captureWarnings(True)  # capture warnings so not in GUI

        logger = logging.getLogger()
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

        # create formatter and add it to the handlers
        execution_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
        formatter = logging.Formatter("%(asctime)s.%(msecs).03d;%(levelname)s;" + execution_id + ";%(message)s", "%Y-%m-%d-%H:%M:%S")

        log_dir_cluster_name = DIR_LOG_SPRINGPATH
        if os.environ.get("CLUSTER_NAME"):
            log_dir_cluster_name = DIR_LOG_SPRINGPATH + '/' + os.environ.get("CLUSTER_NAME")
        if not os.path.exists(log_dir_cluster_name):
            try:
                os.makedirs(log_dir_cluster_name)
            except:
                pass

        # create file handler which logs even debug messages
        if os.path.isdir(log_dir_cluster_name):
            fh = RotatingFileHandler(log_dir_cluster_name + '/' + FILE_LOG, maxBytes=LOG_FILE_MAX_BYTE_COUNT, backupCount=LOG_FILE_BACKUP_COUNT)
        elif os.path.isdir(DIR_LOG):
            fh = RotatingFileHandler(DIR_LOG + '/' + FILE_LOG, maxBytes=LOG_FILE_MAX_BYTE_COUNT, backupCount=LOG_FILE_BACKUP_COUNT)
        else:
            fh = RotatingFileHandler(DIR_TMP + '/' + FILE_LOG, maxBytes=LOG_FILE_MAX_BYTE_COUNT, backupCount=LOG_FILE_BACKUP_COUNT)

        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # create console handler id desired
        if console_logging:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        # create syslog handler id desired
        if syslog_logging:
            logger.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))

    def executeScriptWithResponse(self, script, input_args=None):
        if not os.path.isfile(script):
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INTERNAL_ERROR,
                             "Script  " + script + " not found. Please install scvm client vib.")
        else:
            i = 0
            while True:

                childProcess = None

                process_finalArgs = [script]
                if isinstance(input_args, str):
                    process_finalArgs += [input_args]
                elif isinstance(input_args, list):
                    process_finalArgs += input_args

                logging.debug("Executing process with arguments: " + ', '.join(process_finalArgs))

                childProcess = subprocess.Popen(process_finalArgs, stdout=subprocess.PIPE)

                retVal = childProcess.communicate()[0]
                retCode = childProcess.returncode
                if retCode:
                    if(i < SpringpathNetworkingSetup_VCenter.MAX_RETRIES):
                        i += 1
                        logging.debug("Failed to execute " + script + " script file. Sleeping " + str(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
                                      + " seconds and retrying.")
                        time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
                    else:
                        self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INTERNAL_ERROR,
                                         "Failed to execute " + script + " script file after retrying " + str(SpringpathNetworkingSetup_VCenter.MAX_RETRIES) + " times. Exiting script!!")
                else:
                    return retVal

    def _waitForTask(self, t, task_desc):
        """
        Waits for task to complete.
        """
        logging.info("Waiting for task to complete.")
        # task.WaitForTask(t)
        task.wait_for_task(t)

        if t.info.error:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INTERNAL_ERROR,
                             "Task '{0}' failed. Error: {1}.".format(task_desc, t.info.error))
        else:
            logging.info("Task '{0}' succeeded.".format(task_desc))

    def _reconfigController(self, stCtlVM, vmNetDevChange):
        """
        Helper function to reconfigure a VM after powering it off.
        """
        vmCfgSpec = vim.VirtualMachineConfigSpec()
        vmCfgSpec.deviceChange = vmNetDevChange
        self._reconfigControllerWithSpec(stCtlVM, vmCfgSpec)

    def _reconfigControllerWithSpec(self, stCtlVM, cfgSpec):
        """
        Helper function to reconfigure a VM.
        """
        task = stCtlVM.Reconfigure(cfgSpec)

        self._waitForTask(task, "Reconfiguring controller")

    def _powerOffStCtlVM(self, stCtlVM, shutdown=True):
        """
        Powers off controller.
        """
        if stCtlVM.runtime.powerState == "poweredOff":
            logging.debug("stCtlVM already powered off")
            return

        if shutdown:
            logging.info("Shutting down the stCtlVM")
            stCtlVM.ShutdownGuest()
        else:
            logging.info("Powering Off the stCtlVM")
            t = stCtlVM.PowerOff()
            self._waitForTask(t, "Powering Off the stCtlVM")

        count = 1
        while stCtlVM.runtime.powerState != vim.VirtualMachinePowerState.poweredOff and count < SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
            logging.debug("Waiting for stCtlVM {0} to power down".format(stCtlVM.name))
            time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
            count = count + 1

        if stCtlVM.runtime.powerState != vim.VirtualMachinePowerState.poweredOff:
            logging.error("Failed to poweron stCtlVM")
            return False

    def _powerOffControllers(self):

        # power off controllers in parallel
        threads = []
        stCtlVMs = self._getControllerVMs()
        for stCtlVM in stCtlVMs:
            t = Thread(target=self._powerOffStCtlVM, args=(stCtlVM, True))
            t.start()
            threads.append(t)

        for thread in threads:
            thread.join()

    def _powerOnControllers(self):
        """
        Powers on all controllers in parallel.
        """
        logging.debug("Powering on all controller VMs")

        threads = []
        hosts = self._getHosts()
        for host in hosts:
            stCtlVM = self._getControllerVMOnHost(host)
            if stCtlVM:

                # Only wait for IP after
                # power on if "converged" controller.
                # If compute only controller, we do not
                # wait.
                waitForIpAddr = self._hostRoleIsStorage(host)
                t = Thread(target=self._powerOnStCtlVM, args=(stCtlVM, True, waitForIpAddr))
                t.start()
                threads.append(t)

        for thread in threads:
            thread.join()

    def _powerOnStCtlVM(self, stCtlVM, waitForGuest, waitForIpAddr):
        """
        Powers on controller.
        """
        if SpringpathNetworkingSetup_VCenter.POWER_ON_ESX:
            self._powerOnStCtlVMOnESXi(stCtlVM, waitForGuest, waitForIpAddr)
        else:
            self._powerOnStCtlVMDefault(stCtlVM, waitForGuest, waitForIpAddr)

    def _powerOnStCtlVMOnESXi(self, stCtlVM_Orig, waitForGuest, waitForIpAddr):
        """
        Powers on controller connecting directly to ESXi.
        """
        logging.debug("Attempting to power on controller {0} from ESXi.".format(stCtlVM_Orig.name))

        siOrig = connect.GetSi()

        host_Orig = self._getParentHostForController(stCtlVM_Orig)
        if not host_Orig:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_SYSTEM_ERROR, "Unable to find parent host for controller: {0}".format(stCtlVM_Orig.name))

        index = self._getHostIndexInESXConfigList(host_Orig)
        if index < 0:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_SYSTEM_ERROR, "Unable to find parent host address for controller: {0}".format(stCtlVM_Orig.name))

        esx_host_address = SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST[index]

        hostSi = connect.SmartConnect(host=self._getHostByName(esx_host_address), user=SpringpathNetworkingSetup_VCenter.ESX_USER, pwd=SpringpathNetworkingSetup_VCenter.ESX_PWD)
        host_ESXi = vim.HostSystem('ha-host', hostSi._stub)
        stCtlVM_ESXi = self._getControllerVMOnHost(host_ESXi)
        if not stCtlVM_ESXi:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_SYSTEM_ERROR, "Unable to find controller directly on ESXi host for controller: {0}".format(stCtlVM_Orig.name))

        self._powerOnStCtlVMDefault(stCtlVM_ESXi, waitForGuest, waitForIpAddr)

        connect.SetSi(siOrig)

    def _powerOnStCtlVMDefault(self, stCtlVM, waitForGuest, waitForIpAddr):
        """
        Powers on controller through default connection (VC or ESXi).
        """
        logging.debug("Powering on controller")

        if stCtlVM.runtime.powerState != "poweredOn":
            logging.info("Powering On the stCtlVM")
            t = stCtlVM.PowerOn()
            self._waitForTask(t, "Powering On the stCtlVM")

        stCtlVMUp = self._waitForStCtlVMToPowerOn(stCtlVM, waitForGuest, waitForIpAddr)
        if not stCtlVMUp:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_SYSTEM_ERROR,
                             "stCtlVM and guest OS failed to be ready after attempting powering on.")

    def _waitForStCtlVMToPowerOn(self, stCtlVM, waitForGuest=True, waitForIpAddr=False):
        """
        Waits for controller to power on.
        """
        logging.debug("Waiting for StCtlVM {0} to power on and guest OS be ready.".format(stCtlVM.name))

        count = 1
        while stCtlVM.runtime.powerState != vim.VirtualMachinePowerState.poweredOn and count < SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
            logging.debug("Waiting for stCtlVM {0} to power up".format(stCtlVM.name))
            time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
            count = count + 1

        if stCtlVM.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
            logging.error("Failed to power on stCtlVM {0}".format(stCtlVM.name))
            return False

        if not waitForGuest:
            logging.debug("stCtlVM {0} successfully powered on".format(stCtlVM.name))
            return True

        for reset_try in range(0, 2):
            count = 1
            while stCtlVM.guest.guestState != "running" and count < SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
                logging.debug("Waiting for stCtlVM {0} guest OS to be up".format(stCtlVM.name))
                time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
                count = count + 1

            if stCtlVM.guest.guestState != "running":
                logging.info("Controller VM Hung. Resetting the VM...")
                stCtlVM.ResetVM_Task()
                time.sleep(30)
            else:
                break

        if stCtlVM.guest.guestState != "running":
            logging.error("stCtlVM {0} failed to boot".format(stCtlVM.name))
            return False

        # if not self._waitForStCtlVMHeartBeatToTurnGreen(stCtlVM):
        #     return False

        if not waitForIpAddr:
            logging.debug("stCtlVM {0} guest OS is up".format(stCtlVM.name))
            return True

        count = 1
        while not stCtlVM.guest.ipAddress and count < SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
            logging.debug("Waiting for stCtlVM {0} Guest IP".format(stCtlVM.name))
            time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
            count = count + 1

        if not stCtlVM.guest.ipAddress:
            logging.error("stCtlVM {0} failed to IP address".format(stCtlVM.name))
            return False

        logging.debug("stCtlVM {0} guest IP: {1}".format(stCtlVM.name, stCtlVM.guest.ipAddress))
        return True

    def _waitForStCtlVMHeartBeatToTurnGreen(self, stCtlVM):

        count = 1
        status = stCtlVM.guestHeartbeatStatus
        while status != 'green':

            if count > 15:
                logging.error("Heartbeat status not turning green. Unable to execute command on controller. Verify parameters (e.g. vlan id's) and that VMware Tools is running on controller!")
                return False

            logging.debug("Waiting 30 sec. for guest heartbeat status to turn green")
            time.sleep(10)
            count += 1
            status = stCtlVM.guestHeartbeatStatus

        return True

    # Discovery methods
    # -----------------

    def _getParentHostForController(self, stCtlVM):
        """
        Finds parent host for controller.
        """

        logging.debug("Attempting to find host for controller: {0}.".format(stCtlVM.name))

        hosts = self._getHosts()
        for host in hosts:
            for vm in host.vm:
                if vm._moId == stCtlVM._moId:
                    return host

        return None

    def _getESXiDataCenter(self):
        """
        Gets ESXi datacenter.
        """
        for child_entity in self.si.RetrieveContent().rootFolder.childEntity:
            if type(child_entity) is vim.Datacenter:
                return child_entity

    def _getDataCenter(self, name):
        """
        Gets datacenter of given name.
        """
        return self._getDataCenterFromFolder(name, self.si.RetrieveContent().rootFolder)

    def _getDataCenterFromFolder(self, name, folder):
        """
        Gets datacenter of given name in folder
        if exists there, else returns None.
        """
        child_entities = folder.childEntity
        for child_entity in child_entities:
            if type(child_entity) is vim.Datacenter and child_entity.name == name:
                return child_entity
            elif type(child_entity) is vim.Folder:
                dc = self._getDataCenterFromFolder(name, child_entity)
                if dc:
                    return dc

        return None

    def _getHosts(self):
        """
        Gets all controllers in datacenter.
        """
        logging.debug("Finding all hosts")

        if self.cached_host_list is None:

            self.cached_host_list = []
            self._getHostsInFolder(self.datacenter.hostFolder, self.cached_host_list)
            logging.debug("Found host list {0}".format(self.cached_host_list))
        else:
            logging.debug("Returning cached host list {0}".format(self.cached_host_list))

        return self.cached_host_list

    def _startProgramInGuest(self, processManager, stCtlVM, user, password, cmdspec, ctlVmUserPwd):
        """
        Start programInGuest
        """
        pid = None
        cred = vim.vm.guest.NamePasswordAuthentication(username=user, password=password)
        try:
          pid = processManager.StartProgramInGuest(vm=stCtlVM, auth=cred, spec=cmdspec)
        except Exception:
          if ctlVmUserPwd:
            logging.debug("Trying to login with user defined password")
            cred = vim.vm.guest.NamePasswordAuthentication(username=user, password=ctlVmUserPwd)
            try:
               pid = processManager.StartProgramInGuest(vm=stCtlVM, auth=cred, spec=cmdspec)
            except Exception as e:
               logging.exception('Failed: ' + str(e))
               raise Exception("Failed to login controller VM"+str(e))
        process_exited = False
        count = 0
        while not process_exited and count < SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
          guest_process_info_list = processManager.ListProcessesInGuest(vm=stCtlVM, auth=cred, pids=[pid])
          if len(guest_process_info_list) == 0 or guest_process_info_list[0].exitCode is not None:
             process_exited = True
             return guest_process_info_list[0].exitCode
          else:
             time.sleep(2)
             count = count + 1

    def _autoDiscoverNetworkParamsFromExistingCluster(self):

        logging.error("Attempting to auto-configure parameters from existing cluster.")

        # make sure name of existing cluster is specified
        if not SpringpathNetworkingSetup_VCenter.VCENTER_CLUSTER:
            logging.error("Cannot auto-detect vCenter parameters. Cluster not specified.")
            return False

        # create VI service instance, etc.
        if not self._initialize_VCenter(SpringpathNetworkingSetup_VCenter.VCENTER_HOST,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_USER,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_PWD,
                                        SpringpathNetworkingSetup_VCenter.VCENTER_DATACENTER):
            logging.error("Could not initialize vCenter properly to auto-detect cluster parameters. Check vCenter parameters and that data center exists.")
            return False

        retVal = self._autoDetectNetworkParamsFromExistingCluster(SpringpathNetworkingSetup_VCenter.VCENTER_CLUSTER)
        self.resetScript()

        return retVal

    def _autoDetectNetworkParamsFromExistingCluster(self, cluster_name):
        """
        Auto-detects vSwitches and whether or not
        in VDS configuration from
        an existing cluster.
        """
        switch_name_vlanid_mgmt = None
        switch_name_vlanid_data = None
        on_vds_mgmt = False
        on_vds_data = False
        cluster = self._getCluster(cluster_name)
        if cluster:
            for host in cluster.host:
                stCtlVM = self._getControllerVMOnHost(host)
                if stCtlVM:

                    logging.debug("Checking controller for existing network parameters {0}".format(stCtlVM.name))

                    for device in stCtlVM.config.hardware.device:
                        if device.backing and \
                           type(device.backing) is vim.vm.device.VirtualEthernetCard.NetworkBackingInfo:

                            # TODO:
                            # rely on backing type in the future
                            # to auto-detect instead of pg names.
                            # vim.VirtualVmxnet3
                            # vim.VirtualE1000
                            if device.backing.network and device.backing.network.name == SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT:
                                switch_name_vlanid_mgmt = self.findvSwitchNameAndVlanIDForPortName_Standard(host, SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT)
                            elif device.backing.network and device.backing.network.name == SpringpathNetworkingSetup_VCenter.PG_CTL_DATA:
                                switch_name_vlanid_data = self.findvSwitchNameAndVlanIDForPortName_Standard(host, SpringpathNetworkingSetup_VCenter.PG_CTL_DATA)

                        elif device.backing and \
                                type(device.backing) is vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo and \
                                device.backing.port and \
                                type(device.backing.port) is vim.dvs.PortConnection:

                            switch_name_vlanid = self.findvSwitchNameAndVlanIDForPort_VDS(self.datacenter, SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT, device.backing.port.portgroupKey)
                            if switch_name_vlanid:
                                switch_name_vlanid_mgmt = switch_name_vlanid
                                on_vds_mgmt = True
                            else:
                                switch_name_vlanid = self.findvSwitchNameAndVlanIDForPort_VDS(self.datacenter, SpringpathNetworkingSetup_VCenter.PG_CTL_DATA, device.backing.port.portgroupKey)
                                if switch_name_vlanid:
                                    switch_name_vlanid_data = switch_name_vlanid
                                    on_vds_data = True

                    if on_vds_mgmt != on_vds_data:
                        logging.error("Management and Data networks are mixed between VDS and non-VDS configurations in controller: {}. This is not supported".format(stCtlVM.name))
                    elif not switch_name_vlanid_mgmt:
                        logging.error("Unable to find mgmt vSwitch and vlan ID in existing cluster from controller: {}.".format(stCtlVM.name))
                    elif not switch_name_vlanid_data:
                        logging.error("Unable to find data vSwitch in existing cluster from controller: {}.".format(stCtlVM.name))
                    else:
                        logging.debug("Auto-detected network parameters from existing cluster. "
                                      "mgmt vSwitch: {0}, "
                                      "data vSwitch: {1}, "
                                      "mgmt vlan ID: {2}, "
                                      "data vlan ID: {3}, "
                                      "Is VDS: {4}."
                                      .format(switch_name_vlanid_mgmt[0],
                                              switch_name_vlanid_data[0],
                                              switch_name_vlanid_mgmt[1],
                                              switch_name_vlanid_data[1],
                                              on_vds_data))

                        SpringpathNetworkingSetup_VCenter.VDS_CONFIGURATION = on_vds_data
                        SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT = switch_name_vlanid_mgmt[0]
                        SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA = switch_name_vlanid_data[0]
                        SpringpathNetworkingSetup_VCenter.VLANID_CTL_MGMT = switch_name_vlanid_mgmt[1]
                        SpringpathNetworkingSetup_VCenter.VLANID_CTL_DATA = switch_name_vlanid_data[1]
                        return True

            return False
        else:
            logging.error("Unable to find cluster: {} in datacenter: {}".format(cluster_name, self.datacenter.name))
            return False

    def findvSwitchNameAndVlanIDForPort_VDS(self, datacenter, pg_name, pg_key):

        for network_entity in datacenter.network:
            if network_entity._moId == pg_key and network_entity.name == pg_name:
                return (network_entity.config.distributedVirtualSwitch.name, network_entity.config.defaultPortConfig.vlan.vlanId)

        return None

    def findvSwitchNameAndVlanIDForPortName_Standard(self, host, pg_name):

        for pg in host.config.network.portgroup:
            if pg.spec.name == pg_name:
                return (pg.spec.vswitchName, pg.spec.vlanId)

        return None

    def _getCluster(self, cluster_name):
        """
        Finds cluster of given name
        in datacenter.
        """
        logging.debug("Attempting to find cluster {} in datacenter.".format(cluster_name))

        return self._getClusterInFolder(self.datacenter.hostFolder, cluster_name)

    def _getClusterInFolder(self, folder, cluster_name):
        """
        Finds cluster of given name
        in folder.
        """
        for child_entity in folder.childEntity:

            if type(child_entity) is vim.ClusterComputeResource and child_entity.name == cluster_name:
                return child_entity
            elif type(child_entity) is vim.Folder:
                cluster = self._getClusterInFolder(child_entity, cluster_name)
                if cluster:
                    return cluster

        return None

    def _getHostsInFolder(self, folder, hosts):
        """
        Finds all hosts in given
        folder, searching through
        clusters and sub-folders.

        We check both against host name and
        host IP on individual vnics since the
        name may not match in cases such as DHCP.
        """

        for child_entity in folder.childEntity:

            if type(child_entity) is vim.Folder:

                self._getHostsInFolder(child_entity, hosts)

            elif type(child_entity) is vim.ClusterComputeResource:

                for host in child_entity.host:
                    if self._hostMatchesNameInEsxList(host):
                        logging.debug("Found specified clustered host: {0}".format(host.name))
                        hosts.append(host)

            elif type(child_entity) is vim.HostSystem:

                if self._hostMatchesNameInEsxList(child_entity):
                    logging.debug("Found specified host: {0}".format(child_entity.name))
                    hosts.append(child_entity)

            elif type(child_entity) is vim.ComputeResource:

                for host in child_entity.host:
                    if self._hostMatchesNameInEsxList(host):
                        logging.debug("Found specified non-clustered host: {0}".format(host.name))
                        hosts.append(host)

    def _getControllerVMs(self):
        """
        Gets all controllers in datacenter
        from user specified hosts.
        """
        hosts = self._getHosts()

        logging.debug("Finding all controller VMs based on hosts specified: {0}".format(hosts))

        if self.cached_vm_list is None:
            self.cached_vm_list = []
            for host in hosts:
               vm = self._getControllerVMOnHost(host)
               if vm:
                  self.cached_vm_list.append(vm)
        else:
            logging.debug("Returning cached VM list {0}".format(self.cached_vm_list))

        return self.cached_vm_list

    def _getControllerVMsInCluster(self, cluster):
        """
        Gets all controllers in datacenter
        in given cluster.
        """
        logging.debug("Finding all controllers on all hosts in cluster: {0}.".format(cluster.name))

        vms = []
        for host in cluster.host:
            vm = self._getControllerVMOnHost(host)
            if vm:
                vms.append(vm)

        return vms

    def _getControllerVMOnHost(self, host):
        """
        Gets controller in datacenter
        on given host.
        """
        logging.debug("Attempting to find controller on host: {0}.".format(host.name))

        for vm in host.vm:
            if SpringpathNetworkingSetup_VCenter.STCTLVM_PREFIX in vm.name.upper():
                logging.debug("Found controller VM: {0} on host: {1}".format(vm.name, host.name))
                return vm

        logging.debug("Unable to find controller VM on host: {0}.".format(host.name))
        return None

    def _getHostIndexInESXConfigList(self, host):
        """
        Gets IP index of the host in
        the original configuration list
        that was parsed.
        """
        for index, host_name in enumerate(SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST):

            if self._hostMatchesName(host, host_name):
                return index

        return -1

    def _getControllerDataIPForHost(self, host):
        """
        Gets specified controller data
        IP for host or ""
        if none specified.
        """
        index = self._getHostIndexInESXConfigList(host)
        if index == -1 or len(SpringpathNetworkingSetup_VCenter.IP_CTL_DATA) < index:
            return ""
        else:
            return SpringpathNetworkingSetup_VCenter.IP_CTL_DATA[index]

    def _getControllerMgmtIPForHost(self, host):
        """
        Gets specified controller mgmt
        IP for host or ""
        if none specified.
        """
        index = self._getHostIndexInESXConfigList(host)
        if index == -1 or len(SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT) < index:
            return ""
        else:
            return SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT[index]

    def _getDistributedVirtualSwitch(self, switch_name):
        """
        Gets vswitch of given name in the datacenter.
        """
        child_entities = self.datacenter.networkFolder.childEntity
        for child_entity in child_entities:
            if type(child_entity) is vim.dvs.VmwareDistributedVirtualSwitch and child_entity.name == switch_name:
                return child_entity

        return None

    def _getDistributedPortGroupKVPairs(self):
        """
        Returns all distributed port groups
        in the datacenter as key-value pairs.
        """
        pg_kv_pairs = {}
        for network_entity in self.datacenter.network:
            if type(network_entity) is vim.dvs.DistributedVirtualPortgroup:
                pg_kv_pairs[network_entity.key] = network_entity

        return pg_kv_pairs

    def _getDistributedPortGroupByName(self, pg_name):
        """
        Returns distributed PG based on name.
        """
        for network_entity in self.datacenter.network:

            if type(network_entity) is vim.dvs.DistributedVirtualPortgroup and network_entity.name == pg_name:
                return network_entity

        return None

    def _getDistributedPortGroupByKey(self, pg_key):
        """
        Returns distributed PG based on key.
        """
        for network_entity in self.datacenter.network:

            if type(network_entity) is vim.dvs.DistributedVirtualPortgroup and network_entity.key == pg_key:
                return network_entity

        return None

    def _getStandardPortGroupByName(self, host, pg_name):
        """
        Returns standard port group on given host.
        """
        for portgroup in host.config.network.portgroup:
            if portgroup.spec.name == pg_name:
                return portgroup

        return None

    def _isPortGroupConfiguredOnVDSSwitch(self, pg_name, switch_name, vlanId):
        """
        Returns true if specified port group is
        on switch and false otherwise.
        """
        for network_entity in self.datacenter.network:

            if type(network_entity) is vim.dvs.DistributedVirtualPortgroup and \
                    network_entity.name == pg_name and \
                    network_entity.config.distributedVirtualSwitch.name == switch_name and \
                    network_entity.config.defaultPortConfig.vlan.vlanId == vlanId:

                return True

        return False

    def _isPortGroupConfiguredOnStandardSwitch(self, host, pg_name, switch_name, vlanId):
        """
        Returns true if standard port
        group on given host is on
        given switch.
        """
        for portgroup in host.config.network.portgroup:
            if portgroup.spec.name == pg_name \
                    and portgroup.spec.vswitchName == switch_name \
                    and portgroup.spec.vlanId == vlanId:
                return True

        return False

    # Controller Already Configured Check Methods
    # -------------------------------------------

    def _isControllerConfigured(self, stCtlVM):
        """
        Returns true if the controller
        was already determined
        to be configured, else
        returns false.
        """
        return len([v for v in self.configured_host_ctl_pairs if v[1].name == stCtlVM.name]) > 0

    def _isHostControllerConfigured(self, host):
        """
        Returns true if the controller
        on the specified host
        was already determined
        to be configued, else
        returns false.
        """
        return len([v for v in self.configured_host_ctl_pairs if v[0].name == host.name]) > 0

    def _hasGuestConfiguration(self, stCtlVM, device, pg_name, ipaddr, dns_host_list, dns_search_list):
        """
        Checks to see if has specified
        guest configuration.
        """
        if stCtlVM.guest:
            for guest_nicinfo in stCtlVM.guest.net:

                if guest_nicinfo.macAddress == device.macAddress and \
                    guest_nicinfo.network == pg_name and \
                        (not ipaddr or len(ipaddr) == 0 or self._getHostByName(ipaddr) in guest_nicinfo.ipAddress):
                    return True

        return False

    def _initializeConfiguredHostControllerPairs_Standard(self):
        """
        This method checks which controllers
        are already configured and does not
        try to re-confgure if already done so.
        It performs the following:

        1. Checks that there are exactly two vnics
        2. Checks that one of the vnics is on the specified mgmt vswitch/port
        3. Checks that the other of the vnics is on the specified data vswitch/port
        4. Verifies that IP is set correctly (if static)
        5. Verifies that the DNS host and search strings have not changed
        """
        logging.debug("Checking which controllers are already configured with standard networking.")

        self.configured_host_ctl_pairs = []
        hosts = self._getHosts()
        for host in hosts:

            mgmt_vnic_configured = False
            data_vnic_configured = False
            other_vnic_configured = False

            stCtlVM = self._getControllerVMOnHost(host)
            for device in stCtlVM.config.hardware.device:

                if device.backing and \
                        type(device.backing) is vim.vm.device.VirtualEthernetCard.NetworkBackingInfo:

                    if self._hasNetDeviceConfigured_Standard(host,
                                                             stCtlVM,
                                                             device,
                                                             SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                                             SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                                             self._getControllerMgmtIPForHost(host),
                                                             SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                                             SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST):

                        mgmt_vnic_configured = True
                    elif self._hasNetDeviceConfigured_Standard(host,
                                                               stCtlVM,
                                                               device,
                                                               SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                                               SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                                               self._getControllerDataIPForHost(host),
                                                               SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                                               SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST):

                        data_vnic_configured = True
                    else:
                        other_vnic_configured = True

            if not (mgmt_vnic_configured and data_vnic_configured and not other_vnic_configured):
                logging.debug("The following controller: {0}  on host: {1} IS NOT configured properly.".format(stCtlVM.name, host.name))
            else:
                logging.debug("The following controller: {0}  on host: {1} IS configured properly.".format(stCtlVM.name, host.name))
                self.configured_host_ctl_pairs.append((host, stCtlVM))

    def _hasNetDeviceConfigured_Standard(self, host, stCtlVM, device, switch_name, pg_name, ipaddr, dns_host_list, dns_search_list):
        """
        Checks to see that std.
        port group of given
        name exists on std.
        vSwitch of given name and
        also that guest configuration
        is correct (right IP, MAC, etc).
        """
        for portgroup in host.config.network.portgroup:
            if portgroup.spec.name == pg_name and \
                    portgroup.spec.vswitchName == switch_name and \
                    self._deviceMatchesPortGroup_Standard(portgroup, device) and \
                    self._hasGuestConfiguration(stCtlVM, device, pg_name, ipaddr, dns_host_list, dns_search_list):

                return True

        return False

    def _deviceMatchesPortGroup_Standard(self, portgroup, device):
        """
        Checks that vnic devices is
        located on specified standard port,
        """
        return device.backing.deviceName == portgroup.spec.name

    def _initializeConfiguredHostControllerPairs_VDS(self):
        """
        This method checks which controllers
        are already configured and does not
        try to re-configure if already done so.
        It performs the following:

        1. Checks that there are exactly two vnics
        2. Checks that one of the vnics is on the specified mgmt vswitch/port
        3. Checks that the other of the vnics is on the specified data vswitch/port
        4. Verifies that IP is set correctly (if static)
        """

        logging.debug("Checking which controllers are already configured with VDS networking.")

        self.configured_host_ctl_pairs = []
        hosts = self._getHosts()
        for host in hosts:

            mgmt_vnic_configured = False
            data_vnic_configured = False
            other_vnic_configured = False

            stCtlVM = self._getControllerVMOnHost(host)
            for device in stCtlVM.config.hardware.device:

                if device.backing and \
                        type(device.backing) is vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo and \
                        device.backing.port and \
                        type(device.backing.port) is vim.dvs.PortConnection:

                    if self._hasNetDeviceConfigured_VDS(host,
                                                        stCtlVM,
                                                        device,
                                                        SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                                        SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                                        self._getControllerMgmtIPForHost(host),
                                                        SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                                        SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST):

                        mgmt_vnic_configured = True

                    elif self._hasNetDeviceConfigured_VDS(host,
                                                          stCtlVM,
                                                          device,
                                                          SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                                          SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                                          self._getControllerDataIPForHost(host),
                                                          SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                                          SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST):

                        data_vnic_configured = True
                    else:
                        other_vnic_configured = True

            if not (mgmt_vnic_configured and data_vnic_configured and not other_vnic_configured):
                logging.debug("The following controller: {0}  on host: {1} IS NOT configured properly.".format(stCtlVM.name, host.name))
            else:
                logging.debug("The following controller: {0}  on host: {1} IS configured properly.".format(stCtlVM.name, host.name))
                self.configured_host_ctl_pairs.append((host, stCtlVM))

    def _hasNetDeviceConfigured_VDS(self, host, stCtlVM, device, switch_name, pg_name, ipaddr, dns_host_list, dns_search_list):
        """
        Checks to see that std.
        port group of given
        name exists on std.
        vSwitch of given name and
        also that guest configuration
        is correct (right IP, MAC, etc).
        """
        for pg_key, portgroup in self._getDistributedPortGroupKVPairs().iteritems():

            if portgroup.name == pg_name and \
                    portgroup.config.distributedVirtualSwitch.name == switch_name and \
                    self._deviceMatchesPortGroup_VDS(portgroup, device) and \
                    self._hasGuestConfiguration(stCtlVM, device, pg_name, ipaddr, dns_host_list, dns_search_list):

                return True

        return False

    def _deviceMatchesPortGroup_VDS(self, portgroup, device):
        """
        Checks that vnic devices is
        located on specified VDS port,
        """
        if device.backing.port.portgroupKey and \
                device.backing.port.portgroupKey == portgroup.key:
            return True
        else:
            return False

    # vSwitch Configuration Methods
    # -----------------------------

    def _configureVswitch_Standard(self, host, switch_name, nic_names, nic_order, load_balancing_policy, notify_switches, num_ports, mtu):
        """
        Creates a vSwitch on a given ESXi Host if it doesn't exist
        Updates a vSwitch on a given ESXi Host if pNIC is specified and it exists
        """
        for nic_name in nic_names:
            if nic_name and not self._pnicExists(host, nic_name):
                # self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                print("Unable to find physical NIC {} on host: {}.\n".format(nic_name, host.name))

        isExists = self._switchExists_Standard(host, switch_name)

        if (not isExists and not nic_names):
            self._addVswitch_Standard(host, switch_name, None, None, None, None, num_ports, mtu)

        elif (not isExists and nic_names):
            self._addVswitch_Standard(host, switch_name, nic_names, nic_order,
                                      load_balancing_policy, notify_switches, num_ports, mtu)

        elif (isExists and nic_names):
            self._updateVswitch_Standard(host, switch_name, nic_names, nic_order,
                                         load_balancing_policy, notify_switches, num_ports, mtu)
        else:
            logging.info("Skipping vSwitch {} configuration as it exists on host {}".format(switch_name, host))

    def _getNicFailoverOrder(self, nic_names, nic_order):
        count = 0
        _activeNic = []
        _standbyNic = []
        for nic in nic_names:
            if nic_order[count] == 'active':
                _activeNic.append(nic)
            elif nic_order[count] == 'standby':
                _standbyNic.append(nic)
            else:
                print("_getNicFailoverOrder: Invalid nic order key")
            count = count + 1
        return (_activeNic, _standbyNic)

    def _addVswitch_Standard(self, host, switch_name, nic_names, nic_order, load_balancing_policy, notify_switches, num_ports, mtu):

        logging.debug("Creating vSwitch: {} pNic: {} on host: {}".format(switch_name, nic_names, host))
        logging.debug("_addVswitch_Standard: nic_order: {}, load_balanceing_policy: {}, notify_switches: "
        "{}, num_ports: {}, mtu: {}".format(nic_order, load_balancing_policy, notify_switches, num_ports, mtu))

        vswitch_spec = vim.HostVirtualSwitchSpec()
        vswitch_spec.numPorts = num_ports

        # A bridge connects a virtual switch to a physical network adapter
        if nic_names:
            vswitch_spec.bridge = vim.host.VirtualSwitch.BondBridge(nicDevice=nic_names)

            if nic_order:
                (_activeNic, _standbyNic) = self._getNicFailoverOrder(nic_names, nic_order)
                vswitch_spec.policy = self._createHostNetworkPolicy(_activeNic, _standbyNic, load_balancing_policy, notify_switches)

        vswitch_spec.mtu = int(mtu)

        host.configManager.networkSystem.AddVirtualSwitch(vswitchName=switch_name, spec=vswitch_spec)
        logging.info("Successfully created vSwitch: {} on host: {}".format(switch_name, host))

    def _updateVswitch_Standard(self, host, switch_name, nic_names, nic_order, load_balancing_policy, notify_switches, num_ports, mtu):

        logging.debug("Updating vSwitch: {} pNic: {} on host: {}".format(switch_name, nic_names, host))
        logging.debug("_updateVswitch_Standard: nic_order: {}, load_balanceing_policy: {}, notify_switches: "
        "{}, num_ports: {}, mtu: {}".format(nic_order, load_balancing_policy, notify_switches, num_ports, mtu))
        vswitch_spec = vim.HostVirtualSwitchSpec()
        vswitch_spec.numPorts = num_ports

        if mtu:
            vswitch_spec.mtu = int(mtu)

        # A bridge connects a virtual switch to a physical network adapter
        if nic_names:
            vswitch_spec.bridge = vim.host.VirtualSwitch.BondBridge(nicDevice=nic_names)

            if nic_order:
                (_activeNic, _standbyNic) = self._getNicFailoverOrder(nic_names, nic_order)
                vswitch_spec.policy = self._createHostNetworkPolicy(_activeNic, _standbyNic, load_balancing_policy, notify_switches)

        host.configManager.networkSystem.UpdateVirtualSwitch(vswitchName=switch_name, spec=vswitch_spec)
        logging.debug("Successfully updated vSwitch: {} on host: {}".format(switch_name, host))

    def _createHostNetworkPolicy(self, activeNic, standbyNic, load_balancing_policy, notify_switches):

        nicOrdering = vim.HostNicOrderPolicy()
        nicOrdering.activeNic = activeNic
        nicOrdering.standbyNic = standbyNic

        failureCrit = vim.HostNicFailureCriteria()
        failureCrit.checkBeacon = False
        failureCrit.checkDuplex = False
        failureCrit.checkErrorPercent = False
        failureCrit.checkSpeed = "minimum"
        failureCrit.fullDuplex = False
        failureCrit.percentage = 0
        failureCrit.speed = 10

        nicTeam = vim.HostNicTeamingPolicy()
        nicTeam.nicOrder = nicOrdering
        nicTeam.policy = load_balancing_policy
        nicTeam.reversePolicy = True
        nicTeam.notifySwitches = notify_switches == "true"
        nicTeam.rollingOrder = False
        nicTeam.failureCriteria = failureCrit

        offLoad = vim.HostNetOffloadCapabilities()
        offLoad.csumOffload = True
        offLoad.tcpSegmentation = True
        offLoad.zeroCopyXmit = True

        security = vim.HostNetworkSecurityPolicy()
        security.allowPromiscuous = False
        security.forgedTransmits = True
        security.macChanges = False

        shaping = vim.HostNetworkTrafficShapingPolicy()
        shaping.burstSize = 0
        shaping.enabled = False
        shaping.averageBandwidth = 0
        shaping.peakBandwidth = 0

        hostNetworkPolicy = vim.HostNetworkPolicy()
        hostNetworkPolicy.nicTeaming = nicTeam
        hostNetworkPolicy.offloadPolicy = offLoad
        hostNetworkPolicy.security = security
        hostNetworkPolicy.shapingPolicy = shaping

        return hostNetworkPolicy

    def _configureHXSwitches(self):
        """
        Creates all vSwitches if they do not exist based
        on TUNES file settings. This only
        applies to ALL HX-based hosts and blades
        inventory setup.
        """
        if SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY == SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_HX:

            self._parseVswitchInfoFromTunes()

            # Overwrite mgmt and
            # data vswitch so rest
            # of network portgroup
            # configuration works fine.
            SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT = self.VSWITCH_INFO['vswitch_mgmt']['vswitch']
            SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA = self.VSWITCH_INFO['vswitch_storage_data']['vswitch']

            hosts = self._getHosts()
            for host in hosts:

                # if the HX system has
                # "vSWitch0" and not the management
                # vSwitch, we automatically
                # rename vSwitch0 to
                # the management vSwitch name
                # before doing rest of vSwitch
                # configuration.

                if self._switchExists_Standard(host, SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT_DEFAULT) and \
                        not self._switchExists_Standard(host, SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT):

                    logging.info("Renaming management vSwitch from {} to {} on host {}.".format(SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT_DEFAULT,
                                                                                                SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                                                                                host.name))

                    self._renameDefaultMgmtVswitch(host,
                                                   SpringpathNetworkingSetup_VCenter.ESX_USER,
                                                   SpringpathNetworkingSetup_VCenter.ESX_PWD,
                                                   SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT_DEFAULT,
                                                   SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT)
                # Get vmnics as per pci order
                self._getVswitchInfo(host)

                for vswitch in self.VSWITCH_INFO:

                    nic_order_array = nic_names = None
                    nic_order = self.VSWITCH_INFO[vswitch]['nic_ordering_policy']
                    if nic_order:
                        nic_order_array = nic_order.split(',')

                    pnic_a = self.VSWITCH_INFO[vswitch]['pnic_a']
                    pnic_b = self.VSWITCH_INFO[vswitch]['pnic_b']
                    if pnic_a and pnic_b:
                        nic_names = [pnic_a, pnic_b]
                    else:
                        nic_names = []

                    self._configureVswitch_Standard(host,
                                                    self.VSWITCH_INFO[vswitch]['vswitch'],
                                                    nic_names,
                                                    nic_order_array,
                                                    self.VSWITCH_INFO[vswitch]['load_balancing_policy'],
                                                    self.VSWITCH_INFO[vswitch]['notify_switches'],
                                                    1024,
                                                    self.VSWITCH_INFO[vswitch]['mtu'])

        else:
            logging.info("Skipping vSwitch configuration as it is not an ALL HX-based host inventory.")

    # Port Group Configuration Methods
    # --------------------------------

    def _attachControllersToDistributedDataPG(self, switch_name, pg_name, label, summary):
        """
        Attaches all Controllers to the given distributed data PG.
        """
        logging.debug("Adding all controllers to distributed data port group: {0} on switch: {1}".format(pg_name, switch_name))

        pg = self._getDistributedPortGroupByName(pg_name)
        if not pg:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                             "Unable to attach controllers to distributed mgmt port group. Port group: {0} not found.".format(pg_name))

        netaddspec = self._getStorvisorDataNetworkAddSpec(switch_name, pg_name, label, summary)
        stCtlVMs = self._getControllerVMs()
        for stCtlVM in stCtlVMs:

            if not self._isControllerConfigured(stCtlVM):
                self._attachControllerToPG(stCtlVM, netaddspec, pg_name, pg)
            else:
                logging.debug("The controller {0} is already configured. Will not attach to port group {1}.".format(stCtlVM.name, pg_name))

    def _attachControllerToStandardDataPG(self, host, switch_name, pg_name, label, summary):
        """
        Attaches controller to the given standard data PG on specified host.
        """
        if not self._isHostControllerConfigured(host):

            logging.debug("Adding controller to standard data port group: {0} on switch: {1} on host: {2}".format(pg_name, switch_name, host.name))

            pg = self._getStandardPortGroupByName(host, pg_name)
            if not pg:
                logging.error("Unable to attach controller to standard mgmt port group. Port group: {0} not found on host {1}.".format(pg_name, host.name))
                return

            stCtlVM = self._getControllerVMOnHost(host)
            if not stCtlVM:
                logging.error("Unable to attach controller to standard mgmt port group. Controller not found on host {0}.".format(host.name))
                return

            netaddspec = self._getStorvisorDataNetworkAddSpec(switch_name, pg_name, label, summary, False, False)
            self._attachControllerToPG(stCtlVM, netaddspec, pg_name, pg)
        else:
            logging.debug("The controller on host {0} is already configured. Will not attach to port group {1}.".format(host.name, pg_name))

    def _attachControllersToDistributedMgmtPG(self, switch_name, pg_name, label, summary):
        """
        Attaches all controllers to the given distributed mgmt PG.
        """
        logging.debug("Adding all controllers to distributed mgmt port group: {0} on switch: {1}".format(pg_name, switch_name))

        pg = self._getDistributedPortGroupByName(pg_name)
        if not pg:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                             "Unable to attach contollers to distributed mgmt port group. Port group: {0} not found.".format(pg_name))

        netaddspec = self._getStorvisorMgmtNetworkAddSpec(switch_name, pg_name, label, summary)
        stCtlVMs = self._getControllerVMs()
        for stCtlVM in stCtlVMs:

            if not self._isControllerConfigured(stCtlVM):
                self._attachControllerToPG(stCtlVM, netaddspec, pg_name, pg)
            else:
                logging.debug("The controller {0} is already configured. Will not attach to port group {1}.".format(stCtlVM.name, pg_name))

    def _attachControllerToStandardMgmtPG(self, host, switch_name, pg_name, label, summary):
        """
        Attaches controller to the given
        standard mgmt PG on specified host.
        """
        if not self._isHostControllerConfigured(host):

            logging.debug("Adding controller to standard mgmt port group: {0} on switch: {1} on host: {2}".format(pg_name, switch_name, host.name))

            pg = self._getStandardPortGroupByName(host, pg_name)
            if not pg:
                logging.error("Unable to attach controllers to distributed mgmt port group. Port group: {0} not found.".format(pg_name))
                return

            stCtlVM = self._getControllerVMOnHost(host)
            if not stCtlVM:
                logging.error("Unable to attach controller to standard mgmt port group. Controller not found on host {0}.".format(host.name))
                return

            netaddspec = self._getStorvisorMgmtNetworkAddSpec(switch_name, pg_name, label, summary, False, False)
            self._attachControllerToPG(stCtlVM, netaddspec, pg_name, pg)
        else:
            logging.debug("The controller on host {0} is already configured. Will not attach to port group {1}.".format(host.name, pg_name))

    def _attachControllerToPG(self, stCtlVM, netaddspec, pg_name, pg):
        """
        Attaches controller to the given
        PG if not already attached.
        """

        # Only attach controller if
        # not already attached.
        # Here we check for both VDS
        # and standard PG cases.

        if hasattr(pg, 'vm'):
            for vm in pg.vm:
                if vm._moId == stCtlVM._moId:
                    logging.debug("Controller {0} already attached to PG: {1}. Will not re-attach.".format(stCtlVM._moId, pg_name))
                    return
        else:
            for network in stCtlVM.network:
                if network.name == pg_name:
                    logging.debug("Controller {0} already attached to PG: {1}. Will not re-attach.".format(stCtlVM._moId, pg_name))
                    return

        self._reconfigController(stCtlVM, [netaddspec])

    def _attachHostToDistributedDataPG(self, host, switch_name, pg_name, ipaddress=None):
        """
        Attaches host to the given VDS PG.
        """
        logging.debug("Attempting to set host: {0} to distributed port group: {1}.".format(host.name, pg_name))

        # check to see if vnic with
        # ip parameters already exist.

        if ipaddress:
            ipaddress = socket.gethostbyname(ipaddress)
            vnic_existing = self._getHostVNICWithParameters(host,
                                                            ipaddress,
                                                            SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA,
                                                            SpringpathNetworkingSetup_VCenter.MTU_DATA)

            if vnic_existing and \
                    vnic_existing.spec and \
                    vnic_existing.spec.distributedVirtualPort and \
                    vnic_existing.spec.distributedVirtualPort.portgroupKey:

                port = self._getDistributedPortGroupByKey(vnic_existing.spec.distributedVirtualPort.portgroupKey)
                if port and port.name == pg_name:
                    logging.debug("Host vnic already set on port group with desired IP settings")
                    return
                else:
                    logging.error("Host already has another vnic with desired IP settings")
                    return

        # if host already attached to PG,
        # we simply update it's IP address if
        # specified.

        vnic = self._getHostVnicOnDistributedPG(host, pg_name)
        if not vnic:
            logging.debug("Attaching host: {0} to distributed port group: {1}.".format(host.name, pg_name))

            pg = self._getDistributedPortGroupByName(pg_name)
            if not pg:
                self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                 "Unable to find distributed port group: {0}.".format(pg_name))

            vswitch = self._getDistributedVirtualSwitch(switch_name)
            if not vswitch:
                self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                                 "Unable to find distributed vSwitch group: {0}.".format(switch_name))

            hostVnicSpec = vim.host.VirtualNic.Specification()

            if SpringpathNetworkingSetup_VCenter.MTU_DATA:
                logging.debug("Setting ESXi VNIC mtu size of: {}".format(SpringpathNetworkingSetup_VCenter.MTU_DATA))
                hostVnicSpec.mtu = SpringpathNetworkingSetup_VCenter.MTU_DATA

            hostVnicSpec.distributedVirtualPort = vim.dvs.PortConnection()
            hostVnicSpec.distributedVirtualPort.portgroupKey = pg.key
            hostVnicSpec.distributedVirtualPort.switchUuid = vswitch.uuid
            hostVnicSpec.ip = vim.host.IpConfig()
            if ipaddress and SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA:
                logging.debug("Attaching host: {0} via static IP {1} and netmask {2}.".format(host.name, ipaddress, SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA))
                hostVnicSpec.ip.ipAddress = self._getHostByName(ipaddress)
                hostVnicSpec.ip.subnetMask = SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA
            else:
                logging.debug("Attaching host: {0} via DHCP.".format(host.name))
                hostVnicSpec.ip.dhcp = True

            logging.debug("Adding new host vnic to VDS configuration: {0}".format(hostVnicSpec))
            host.configManager.networkSystem.AddVirtualNic("", hostVnicSpec)
        else:
            logging.debug("Host: {0} already attached to distributed port group: {1}. Setting IP address info.".format(host.name, pg_name))
            hostVnicSpec = vnic.spec

            if SpringpathNetworkingSetup_VCenter.MTU_DATA:
                logging.debug("Setting ESXi VNIC mtu size of: {}".format(SpringpathNetworkingSetup_VCenter.MTU_DATA))
                hostVnicSpec.mtu = SpringpathNetworkingSetup_VCenter.MTU_DATA

            hostVnicSpec.ip = vim.host.IpConfig()
            if ipaddress and SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA:
                logging.debug("Reconfiguring host: {0} via static IP {1} and netmask {2}.".format(host.name, ipaddress, SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA))
                hostVnicSpec.ip.ipAddress = self._getHostByName(ipaddress)
                hostVnicSpec.ip.subnetMask = SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA
            else:
                logging.debug("Reconfiguring host: {0} via DHCP.".format(host.name))
                hostVnicSpec.ip.dhcp = True

            logging.debug("Updating host vnic device: {0} to VDS configuration: {1}".format(vnic.device, hostVnicSpec))
            host.configManager.networkSystem.UpdateVirtualNic(vnic.device, hostVnicSpec)

    def _getHostVNICWithParameters(self, host, ipaddress, netmask, mtu):
        """
        Returns host vnic with given
        IP parameters and None if no
        suitable vnic is found.
        """
        networkSystem = host.configManager.networkSystem

        for vnic in networkSystem.networkInfo.vnic:
            if self._hostVNICHasParameters(vnic, ipaddress, netmask, mtu):
                return vnic

        return None

    def _hostVNICHasParameters(self, vnic, ipaddress, netmask=None, mtu=None):
        """
        Returns true if host vnic has given IP
        parameters and false otherwise.
        """
        if mtu and vnic.spec.mtu != mtu:
            return False

        if netmask:
            if vnic.spec.ip and \
                    vnic.spec.ip.ipAddress == ipaddress and \
                    vnic.spec.ip.subnetMask == netmask:
                return True
        else:
            if vnic.spec.ip and \
                    vnic.spec.ip.ipAddress == ipaddress:
                return True

        return False

    def _attachHostToStandardDataPG(self, host, pg_name, ipaddress=None):
        """
        Attaches host to the given standard
        PG if not already attached.

        If vnic already attached, it will
        simply set the IP.

        Note: It will not attach vnic/set the static IP if
        the host already has a vnic with the same
        static ip already set.
        """
        logging.debug("Attempting to set host: {0} to standard port group: {1}.".format(host.name, pg_name))

        # check to see if vnic with
        # ip parameters already exist.
        if ipaddress:
            ipaddress = self._getHostByName(ipaddress)
            vnic_existing = self._getHostVNICWithParameters(host,
                                                            ipaddress,
                                                            SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA,
                                                            SpringpathNetworkingSetup_VCenter.MTU_DATA)

            if vnic_existing:
                if vnic_existing.portgroup and vnic_existing.portgroup == pg_name:
                    logging.debug("Host vnic already set on port group with desired IP settings")
                    return
                else:
                    logging.error("Host already has another vnic with desired IP settings")
                    return

        vnic = self._getHostVnicOnStandardPG(host, pg_name)
        if not vnic:
            logging.debug("Attaching host: {0} to standard port group: {1}.".format(host.name, pg_name))
            hostVnicSpec = vim.host.VirtualNic.Specification()

            if SpringpathNetworkingSetup_VCenter.MTU_DATA:
                logging.debug("Setting ESXi VNIC mtu size of: {}".format(SpringpathNetworkingSetup_VCenter.MTU_DATA))
                hostVnicSpec.mtu = SpringpathNetworkingSetup_VCenter.MTU_DATA

            hostVnicSpec.portgroup = pg_name
            hostVnicSpec.ip = vim.host.IpConfig()
            if ipaddress and SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA:
                logging.debug("Attaching host: {0} via static IP {1} and netmask {2}.".format(host.name, ipaddress, SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA))
                hostVnicSpec.ip.ipAddress = self._getHostByName(ipaddress)
                hostVnicSpec.ip.subnetMask = SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA
            else:
                logging.debug("Attaching host: {0} via DHCP.".format(host.name))
                hostVnicSpec.ip.dhcp = True

            host.configManager.networkSystem.AddVirtualNic(pg_name, hostVnicSpec)
        else:
            logging.debug("Host: {0} already attached to standard port group: {1}. Just updating IP address info.".format(host.name, pg_name))
            hostVnicSpec = vnic.spec

            if SpringpathNetworkingSetup_VCenter.MTU_DATA:
                logging.debug("Setting ESXi VNIC mtu size of: {}".format(SpringpathNetworkingSetup_VCenter.MTU_DATA))
                hostVnicSpec.mtu = SpringpathNetworkingSetup_VCenter.MTU_DATA

            hostVnicSpec.ip = vim.host.IpConfig()
            if ipaddress and SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA:
                logging.debug("Reconfiguring host: {0} via static IP {1} and netmask {2}.".format(host.name, ipaddress, SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA))
                hostVnicSpec.ip.ipAddress = self._getHostByName(ipaddress)
                hostVnicSpec.ip.subnetMask = SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA
            else:
                logging.debug("Reconfiguring host: {0} via DHCP.".format(host.name))
                hostVnicSpec.ip.dhcp = True

            host.configManager.networkSystem.UpdateVirtualNic(vnic.device, hostVnicSpec)

    def _destroyControllerVNICs(self):
        """
        We destroy all controller VNICs network devices
        on standard and VDS port and
        rebuild them to ensure udev rules
        are correct.
        """
        logging.debug("Detecting and removing all network vnic devices from Springpath controllers")

        self._powerOffControllers()

        stCtlVMs = self._getControllerVMs()
        for stCtlVM in stCtlVMs:

            if not self._isControllerConfigured(stCtlVM):

                devCfgSpecList = []

                for device in stCtlVM.config.hardware.device:

                    if device.backing and type(device.backing) is vim.vm.device.VirtualEthernetCard.NetworkBackingInfo:

                        logging.debug("Detected and removing standard port network device {0} from controller: {1}".format(device.macAddress, stCtlVM.name))
                        devCfgSpecList.append(self._getDeviceRemoveSpec(device))

                    elif device.backing and \
                            type(device.backing) is vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo and \
                            device.backing.port and \
                            type(device.backing.port) is vim.dvs.PortConnection:

                        logging.debug("Detected and removing distributed port network device {0} from controller: {1}".format(device.macAddress, stCtlVM.name))
                        devCfgSpecList.append(self._getDeviceRemoveSpec(device))

                if len(devCfgSpecList) > 0:
                    logging.debug("Reconfiguring controller {0} to change vnic devices.".format(stCtlVM.name))
                    self._reconfigController(stCtlVM, devCfgSpecList)

                self._outputStatusStep('network - destroy controller vnics',
                                       SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                                       stCtlVM.name,
                                       SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_NODE,
                                       stCtlVM.name)
            else:
                logging.debug("The controller {0} is already configured. Will not destroy controller vnics.".format(stCtlVM.name))

    def _removeAllDevicesFromDistributedPGOnForce(self, pg_name):
        """
        Force removes all VMs and hosts
        from distributed PG regardless
        if they are controllers or
        user-specified hosts.
        """
        if SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VM_PORTGROUP or \
                SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VMKERNEL_PORTGROUP:

            pg = self._getDistributedPortGroupByName(pg_name)
            if not pg:
                return

            if SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VM_PORTGROUP:

                self._powerOffControllers()

                for vm in pg.vm:
                    logging.debug("FORCE removing VM {0} from port group: {1}".format(vm.name, pg_name))
                    self._removeVMFromDistributedPG(vm, pg_name, pg)

            if SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VMKERNEL_PORTGROUP:

                for host in pg.host:
                    logging.debug("FORCE removing host {0} from port group: {1}".format(host.name, pg_name))
                    self._removeHostFromDistributedPG(host, pg)

    def _removeVMFromDistributedPG(self, vm, pg_name, pg):
        """
        Removes Springpath controller
        from given distributed
        port group.
        """
        for pg_vm in pg.vm:
            if pg_vm._moId == vm._moId:

                logging.debug("Attempting to find and remove controller: {0}, from network: {1}".format(vm.name, pg_name))

                pg_kv_pairs = self._getDistributedPortGroupKVPairs()

                for device in vm.config.hardware.device:

                    if device.backing and \
                            type(device.backing) is vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo and \
                            device.backing.port and \
                            type(device.backing.port) is vim.dvs.PortConnection and \
                            device.backing.port.portgroupKey in pg_kv_pairs and \
                            pg_kv_pairs[device.backing.port.portgroupKey].name == pg_name:

                        logging.debug("About to remove controller from distributed port group: {0}".format(pg_name))
                        vmNetDevChange = [self._getDeviceRemoveSpec(device)]
                        self._reconfigController(vm, vmNetDevChange)
                        logging.debug("Done removing controller from distributed port group: {0}".format(pg_name))

    def _removeHostsFromDistributedPG(self, pg_name, checkIP=False):
        """
        Removes hosts from given distributed port group.
        """
        pg = self._getDistributedPortGroupByName(pg_name)
        if pg:
            hosts = self._getHosts()
            for host in hosts:
                if checkIP:
                    self._removeHostFromDistributedPG(host, pg, self._getESXDataIPForHost(host))
                else:
                    self._removeHostFromDistributedPG(host, pg)

    def _removeHostFromDistributedPG(self, host, pg, ip=None):
        """
        Removes a host from given distributed port group.
        """
        networkSystem = host.configManager.networkSystem
        for vnic in networkSystem.networkInfo.vnic:
            if hasattr(vnic, 'spec') and \
                    vnic.spec and \
                    vnic.spec.distributedVirtualPort and \
                    vnic.spec.distributedVirtualPort.portgroupKey == pg.key:

                if ip:
                    if vnic.spec.ip and vnic.spec.ip.ipAddress == self._getHostByName(ip):
                        logging.debug("Removing host device '{0}' with ip '{1}'on distributed port group '{2}'".format(vnic.device, ip, pg.name))
                        networkSystem.RemoveVirtualNic(vnic.device)
                else:
                    logging.debug("Removing host device '{0}' on distributed port group '{1}'".format(vnic.device, pg.name))
                    networkSystem.RemoveVirtualNic(vnic.device)

    def _assertDistributedPortGroupHasNoVMDevices(self, pg_name):
        """
        Validate that there
        are no VMs or hosts
        on the distributed
        port group.
        """

        pg = self._getDistributedPortGroupByName(pg_name)
        if pg and len(pg.vm) > 0:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_CLUSTER_INVALID_STATE,
                             "The portgroup {0} has non-Springpath controller VMs attached to it that need to be removed before proceeding. Please remove and re-try again.".format(pg_name))

    def _removeAllVMsFromStandardPGOnForce(self, host, switch_name, pg_name):
        """
        Removes all VMs or specified
        Springpath controllers
        from given standard
        port group.
        """

        # Note: If "force remove port
        # group", we automatically
        # shutdown and remove any
        # VM on the port group.
        # Otherwise, we only remove
        # the controllers that
        # are on the hosts specified.
        if SpringpathNetworkingSetup_VCenter.FORCE_MOVE_VM_PORTGROUP:
            logging.debug("Removing ALL VMs from port group: {0} on switch {1}".format(pg_name, switch_name))

            self._powerOffControllers()
            for vm in host.vm:
                self._removeVMFromStandardPG(vm, pg_name)

    def _removeVMFromStandardPG(self, vm, pg_name):
        """
        Removes Springpath controller
        from given standard
        port group.
        """
        logging.debug("Attempting to find and remove controller: {0}, from network: {1}".format(vm.name, pg_name))

        for device in vm.config.hardware.device:

            if device.backing and \
                    type(device.backing) is vim.vm.device.VirtualEthernetCard.NetworkBackingInfo and \
                    device.backing.network and \
                    device.backing.network.name == pg_name:

                logging.debug("About to remove controller from standard port group: {0}".format(pg_name))
                vmNetDevChange = [self._getDeviceRemoveSpec(device)]
                self._reconfigController(vm, vmNetDevChange)
                logging.debug("Done removing controller from standard port group: {0}".format(pg_name))

    def _removeHostFromStandardPG(self, host, pg_name, ip=None):
        """
        Removes hosts from given
        standard port group.
        """
        networkSystem = host.configManager.networkSystem

        for vnic in networkSystem.networkInfo.vnic:
            if vnic.portgroup == pg_name:
                if ip:
                    if vnic.spec.ip and vnic.spec.ip.ipAddress == self._getHostByName(ip):
                        logging.debug("Removing host device '{0}' with ip '{1}' on standard port group '{2}'".format(vnic.device, ip, pg_name))
                        networkSystem.RemoveVirtualNic(vnic.device)
                else:
                    logging.debug("Removing host device '{0}' on standard port group '{1}'".format(vnic.device, pg_name))
                    networkSystem.RemoveVirtualNic(vnic.device)

    def _assertStandardPortGroupHasNoVMDevices(self, host, pg_name):
        """
        Validate that there
        are no VMs or hosts
        on the standard
        port group.
        """
        for vm in host.vm:

            if vm.config and vm.config.hardware:
                for device in vm.config.hardware.device:
                    if device.backing and \
                            type(device.backing) is vim.vm.device.VirtualEthernetCard.NetworkBackingInfo and \
                            device.backing.network and \
                            device.backing.network.name == pg_name:
                        self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_CLUSTER_INVALID_STATE,
                                         "The portgroup {0} has non-Springpath controller VMs attached to it that need to be removed before proceeding. Please remove and re-try again.".format(pg_name))

    def _getHostVnicOnDistributedPG(self, host, pg_name):
        """
        Returns the host vnic on the given
        distributed PG if exists, else return None.
        """
        networkSystem = host.configManager.networkSystem
        for vnic in networkSystem.networkInfo.vnic:

            # we check both standard and VDS ports
            if vnic.spec and vnic.spec.distributedVirtualPort:
                pg = self._getDistributedPortGroupByName(pg_name)
                if pg and pg.key == vnic.spec.distributedVirtualPort.portgroupKey:
                    return vnic

        return None

    def _getHostVnicOnStandardPG(self, host, pg_name):
        """
        Returns the host vnic on the given
        standard PG if exists, else return None.
        """
        networkSystem = host.configManager.networkSystem
        for vnic in networkSystem.networkInfo.vnic:

            # we check both standard and VDS ports
            if vnic.portgroup == pg_name:
                return vnic

        return None

    def _getDeviceRemoveSpec(self, device):
        """
        Generate a Device removal config spec.
        """
        devCfgSpec = vim.VirtualDeviceConfigSpec()
        devCfgSpec.operation = vim.VirtualDeviceConfigSpecOperation.remove

        devCfgSpec.device = device

        return devCfgSpec

    def _getStorvisorVirtualDeviceConnectInfo(self, connected, startOnConnect):
        """
        Return a virtual device connect info for etherNet virtual adapter
        """
        devConnectSpec = vim.VirtualDeviceConnectInfo()
        devConnectSpec.connected = connected
        devConnectSpec.startConnected = startOnConnect
        devConnectSpec.allowGuestControl = True

        return devConnectSpec


    def _getStorvisorDataNetworkAddSpec(self, switch_name, pg_name, label,
                                        summary, connected = True, startOnConnected = True,
                                        operationType = 'add'):
        """
        Generate a VMXNet3 addition device
        config spec for the Springpath platform.
        """
        devCfgSpec = vim.VirtualDeviceConfigSpec()
        if operationType ==  "add":
            devCfgSpec.operation = vim.VirtualDeviceConfigSpecOperation.add
        elif operationType == "remove":
            devCfgSpec.operation = vim.VirtualDeviceConfigSpecOperation.remove
        else:
            devCfgSpec.operation = vim.VirtualDeviceConfigSpecOperation.edit

        dev = vim.VirtualVmxnet3()
        dev.connectable = self._getStorvisorVirtualDeviceConnectInfo(connected, startOnConnected)

        if self._setupVDSConfiguration():
            dev.backing = self._getDeviceBackingInfo_VDS(switch_name, pg_name)
        else:
            dev.backing = self._getDeviceBackingInfo_Standard(pg_name)

        dev.key = -104
        descr = vim.Description()
        descr.label = label
        descr.summary = summary
        dev.deviceInfo = descr

        devCfgSpec.device = dev

        return devCfgSpec

    def _getStorvisorMgmtNetworkAddSpec(self, switch_name, pg_name, label,
        summary, connected = True, startOnConnected = True, operationType = 'add', deviceKey=-104):
        """
        Generate a VirtualE1000 add/edit
        device config spec for Springpath Mgmt.
        """
        if operationType == 'add':
            devOperation = vim.VirtualDeviceConfigSpecOperation.add
        elif operationType == 'remove':
            devOperation = vim.VirtualDeviceConfigSpecOperation.remove
        else:
            devOperation = vim.VirtualDeviceConfigSpecOperation.edit

        devCfgSpec = vim.VirtualDeviceConfigSpec()
        devCfgSpec.operation = devOperation

        dev = vim.VirtualE1000()
        dev.connectable = self._getStorvisorVirtualDeviceConnectInfo(connected, startOnConnected)

        if self._setupVDSConfiguration():
            dev.backing = self._getDeviceBackingInfo_VDS(switch_name, pg_name)
        else:
            dev.backing = self._getDeviceBackingInfo_Standard(pg_name)

        dev.key = deviceKey
        descr = vim.Description()
        descr.label = label
        descr.summary = summary
        dev.deviceInfo = descr

        devCfgSpec.device = dev

        return devCfgSpec

    def _getDeviceBackingInfo_Standard(self, pg_name):

        backing = vim.VirtualEthernetCardNetworkBackingInfo()
        backing.deviceName = pg_name

        return backing

    def _getDeviceBackingInfo_VDS(self, switch_name, pg_name):

        vswitch = self._getDistributedVirtualSwitch(switch_name)
        if not vswitch:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                             "Unable to find vswitch to which to connect VM: {0}".format(switch_name))

        pg = self._getDistributedPortGroupByName(pg_name)
        if not pg:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                             "Unable to find port group to which to connect VM: {0}".format(pg_name))

        backing = vim.VirtualEthernetCardDistributedVirtualPortBackingInfo()
        backing.port = vim.DistributedVirtualSwitchPortConnection()
        backing.port.switchUuid = vswitch.uuid
        backing.port.portgroupKey = pg.key

        return backing

    def _deletePG_VDS(self, pg_name):
        """
        Deletes a distributed port group with given name in datacenter.
        It first removes any hosts and other vms if "force"
        option used. We assume the controller VMs are already
        detached from any port groups at this point, so we do not
        need to remove them.
        """
        logging.debug("Attempting to delete distributed port group: {0} in the datacenter if exists.".format(pg_name))

        self._removeHostsFromDistributedPG(pg_name, False)
        self._removeAllDevicesFromDistributedPGOnForce(pg_name)
        self._assertDistributedPortGroupHasNoVMDevices(pg_name)

        for network_entity in self.datacenter.network:

            if type(network_entity) is vim.dvs.DistributedVirtualPortgroup and network_entity.name == pg_name:
                self._waitForTask(network_entity.Destroy(), "Destroy distributed port group: {0}".format(pg_name))

    def _deletePG_Standard(self, host, switch_name, pg_name):
        """
        Deletes a port group with given name on standard vSwitch.
        It first removes the host and any other vms if "force"
        option used. We assume controller VMs is already
        detached from any port groups at this point, so we do not
        need to remove them.

        Since this is a "standard" switch, we do not have to worry about
        other hosts attached to the port group other than the one
        who owns this switch (unlike in VDS case).
        """
        self._removeHostFromStandardPG(host, pg_name)  # in case host VMKernel port, remove it
        self._removeAllVMsFromStandardPGOnForce(host, switch_name, pg_name)
        self._assertStandardPortGroupHasNoVMDevices(host, pg_name)

        networkSystem = host.configManager.networkSystem
        try:
            for pg in networkSystem.networkInfo.portgroup:
                if pg.spec.name == pg_name:
                    logging.debug("Removing port group: {0} on host: {1}".format(pg_name, host.name))
                    networkSystem.RemovePortGroup(pg_name)

        except vim.fault.ResourceInUse:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_CLUSTER_INVALID_STATE,
                             "Cannot delete port group: {0} on host: {1}. Make sure there are no VMs attached to it except for the Springpath controller.".format(pg_name, host.name))

    def _createPG_VDS(self, switch_name, pg_name, pg_desc, vlanId):
        """
        Create a Springpath port group
        with given name and vlan id on
        given VDS  vswitch,
        """
        logging.debug("Creating distributed port group: {0} on switch: {1}.".format(pg_name, switch_name))

        pgSpec = vim.dvs.DistributedVirtualPortgroup.ConfigSpec()
        pgSpec.name = pg_name
        pgSpec.numPorts = SpringpathNetworkingSetup_VCenter.NUM_PG_PORTS
        pgSpec.description = pg_desc
        pgSpec.autoExpand = True
        pgSpec.type = vim.dvs.DistributedVirtualPortgroup.PortgroupType.earlyBinding
        pgSpec.defaultPortConfig = vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy()
        pgSpec.defaultPortConfig.vlan = vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec()
        pgSpec.defaultPortConfig.vlan.vlanId = vlanId
        pgSpec.defaultPortConfig.securityPolicy = vim.dvs.VmwareDistributedVirtualSwitch.SecurityPolicy()
        pgSpec.defaultPortConfig.securityPolicy.forgedTransmits = vim.BoolPolicy()
        pgSpec.defaultPortConfig.securityPolicy.forgedTransmits.value = True

        switch = self._getDistributedVirtualSwitch(switch_name)
        if switch:
            try:
                self._waitForTask(switch.CreateDVPortgroup_Task(pgSpec), "Creating distributed port group {0}".format(pg_name))
            except vim.fault.DuplicateName:
                logging.error("Duplicate name exception since distributed port group {0} already created in parallel. Will continue configuration.".format(pg_name))
        else:
            self.handleError(SpringpathNetworkingSetup_VCenter.STEXCEPTIONID_INVALID_ARGUMENT,
                             "Unable to create distributed port group {0}. Switch {1} not found.".format(pg_name, switch_name))

    def _createPG_Standard(self, host, switch_name, pg_name, vlanId):
        """
        Create a Springpath port group
        with given name and vlan id on
        given standard  vswitch,
        """
        logging.debug("Creating standard port group: {0} on host: {1}.".format(pg_name, host.name))

        networkSystem = host.configManager.networkSystem
        pgSpec = vim.HostPortGroupSpec()
        pgSpec.name = pg_name
        pgSpec.vlanId = vlanId
        pgSpec.vswitchName = switch_name
        pgSpec.policy = vim.HostNetworkPolicy()
        networkSystem.AddPortGroup(pgSpec)

    def _setPgOnSwitch_VDS(self, switch_name, pg_name, vlanId):

        logging.debug("Ensuring port group: {0} is set on switch: {1}.".format(pg_name, switch_name))

        # if PG not already on specified
        # switch, we delete it and
        # recreate no the specified switch.
        if not self._isPortGroupConfiguredOnVDSSwitch(pg_name, switch_name, vlanId):

            logging.debug("Port group: {0} is not correctly configured on switch: {1}. Will (re)create or move it.".format(pg_name, switch_name))
            self._deletePG_VDS(pg_name)
            self._createPG_VDS(switch_name, pg_name, pg_name, vlanId)
        else:
            logging.debug("Port group: {0} is already correctly configured on switch: {1}. Will not move it.".format(pg_name, switch_name))

    def _setPgOnSwitch_Standard(self, host, switch_name, pg_name, vlanId):

        # ensure we reset the VLAN ID
        # for existing port groups
        # in case it was different from
        # before
        self._resetPG_VLAN_Standard(host, pg_name, switch_name, vlanId)

        if not self._isPortGroupConfiguredOnStandardSwitch(host, pg_name, switch_name, vlanId):

            logging.debug("Port group: {0} is not correctly configured on switch: {1} for host: {2}. Will (re)create or move it.".format(pg_name, switch_name, host.name))
            self._deletePG_Standard(host, switch_name, pg_name)
            self._createPG_Standard(host, switch_name, pg_name, vlanId)
        else:
            logging.debug("Port group: {0} is already correctly configured on standard switch: {1} for host: {2}. Will not move it.".format(pg_name, switch_name, host.name))

    def _configureMgmtPG_VDS(self, switch_name, pg_name, vnic_label, vnic_summary, vlanId, attachController=True):

        logging.debug("Configuring VDS controller mgmt port group: {0} on switch: {1}.".format(pg_name, switch_name))

        # set PG on correct switch, if not there already.
        self._setPgOnSwitch_VDS(switch_name, pg_name, vlanId)

        if attachController:
            # attach all controllers to PG
            self._powerOffControllers()
            self._attachControllersToDistributedMgmtPG(switch_name,
                                                       pg_name,
                                                       vnic_label,
                                                       vnic_summary)

    def _configureDataPG_VDS(self, switch_name, pg_name, vnic_label, vnic_summary, vlanId, attachController=True):

        logging.debug("Configuring VDS controller data port group: {0} on switch: {1}.".format(pg_name, switch_name))

        # set PG on correct switch, if not there already.
        self._setPgOnSwitch_VDS(switch_name, pg_name, vlanId)

        if attachController:
            # attach all controllers to PG
            self._powerOffControllers()
            self._attachControllersToDistributedDataPG(switch_name,
                                                       pg_name,
                                                       vnic_label,
                                                       vnic_summary)

    def _configureDataPG_VDS_ESX(self, switch_name, pg_name, vlanId):

        logging.debug("Configuring VDS ESX data port group: {0} on switch: {1}.".format(pg_name, switch_name))

        # set PG on correct switch,
        # if not there already.
        self._setPgOnSwitch_VDS(switch_name, pg_name, vlanId)

        hosts = self._getHosts()
        for host in hosts:

            # In case the host is already attached to std pg
            # of same name with same IP, we remove it. This allows
            # for seamless migration from std networking to
            # VDS networking.
            self._removeHostFromStandardPG(host, pg_name, self._getESXDataIPForHost(host))
            self._attachHostToDistributedDataPG(host, switch_name, pg_name, self._getESXDataIPForHost(host))

    def _configureVMotionPG_Standard(self, switch_name, pg_name, vlanId):

        logging.debug("Configuring standard controller vmotion port group: {0} on switch: {1}.".format(pg_name, switch_name))

        hosts = self._getHosts()
        for host in hosts:

            # set PG on correct switch, if not there already.
            self._setPgOnSwitch_Standard(host, switch_name, pg_name, vlanId)
            self._outputStatusStep('network - setup host controller vmotion port group',
                                   SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                                   host.name,
                                   SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_VIRTNODE,
                                   host.name)

    def _configureVMPG_Standard(self, switch_name, pg_info_list):

        logging.debug("Configuring standard controller VM port group list on switch: {}.".format(switch_name))

        hosts = self._getHosts()
        for host in hosts:

            for pg_info in pg_info_list:
                self._setPgOnSwitch_Standard(host, switch_name, pg_info['pg_name'], pg_info['vlanid'])

            self._outputStatusStep('network - setup host controller VM port groups',
                                   SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                                   host.name,
                                   SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_VIRTNODE,
                                   host.name)

    def _configureMgmtPG_Standard(self, switch_name, pg_name, vnic_label, vnic_summary, vlanId, attachController=True):

        logging.debug("Configuring standard controller mgmt port group: {0} on switch: {1}.".format(pg_name, switch_name))

        # power off all controllers
        # if being attached
        if attachController:
            self._powerOffControllers()

        hosts = self._getHosts()
        for host in hosts:

            # set PG on correct switch, if not there already.
            self._setPgOnSwitch_Standard(host, switch_name, pg_name, vlanId)

            if attachController:
                # attach controller to PG
                self._attachControllerToStandardMgmtPG(host,
                                                       switch_name,
                                                       pg_name,
                                                       vnic_label,
                                                       vnic_summary)

            self._outputStatusStep('network - setup host controller management port group',
                                   SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                                   host.name,
                                   SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_VIRTNODE,
                                   host.name)

    def _configureDataPG_Standard(self, switch_name, pg_name, vnic_label, vnic_summary, vlanId, attachController=True):

        logging.debug("Configuring standard controller data port group: {0} on switch: {1}.".format(pg_name, switch_name))

        # power off all controllers
        # if being attached
        if attachController:
            self._powerOffControllers()

        hosts = self._getHosts()
        for host in hosts:

            # set PG on correct switch, if not there already.
            self._setPgOnSwitch_Standard(host, switch_name, pg_name, vlanId)

            if attachController:
                # attach controller to PG
                self._attachControllerToStandardDataPG(host,
                                                       switch_name,
                                                       pg_name,
                                                       vnic_label,
                                                       vnic_summary)

            self._outputStatusStep('network - setup host controller data port group',
                                   SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                                   host.name,
                                   SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_VIRTNODE,
                                   host.name)

    def _configureDataPG_Standard_ESX(self, switch_name, pg_name, vlanId):

        logging.debug("Configuring standard ESX data port group: {0} on switch: {1}.".format(pg_name, switch_name))

        hosts = self._getHosts()
        for host in hosts:

            # set PG on correct switch,
            # if not there already.
            self._setPgOnSwitch_Standard(host, switch_name, pg_name, vlanId)
            self._attachHostToStandardDataPG(host, pg_name, self._getESXDataIPForHost(host))

            self._outputStatusStep('network - setup host VMKernel data port group',
                                   SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                                   host.name,
                                   SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_VIRTNODE,
                                   host.name)

        logging.debug("Done configuring ESXi Data Network.")

    def _resetPG_VLAN_Standard(self, host, pg_name, switch_name, vlanId):
        """
        This method resets VLAN ID on the port group on the given
        switch for the given host if it exists and the VLAN ID is
        different.
        """

        logging.debug("Checking if VLAN ID reset needed - host: {}, switch: {}, port group: {}, vlanid: {}.".format(host.name, switch_name, pg_name, vlanId))

        for portgroup in host.config.network.portgroup:

            if portgroup.spec.name == pg_name and portgroup.spec.vswitchName == switch_name:

                if portgroup.spec.vlanId != vlanId:

                    logging.debug("Resetting VLAN ID - host: {}, switch: {}, port group: {}, vlanid: {}.".format(host.name, switch_name, pg_name, vlanId))

                    networkSystem = host.configManager.networkSystem
                    portgroup.spec.vlanId = vlanId
                    networkSystem.UpdatePortGroup(portgroup.spec.name, portgroup.spec)

    def _getESXDataIPForHost(self, host):

        for index, host_name in enumerate(SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST):

            if self._hostMatchesName(host, host_name) and \
               SpringpathNetworkingSetup_VCenter.IP_ESX_DATA and \
               len(SpringpathNetworkingSetup_VCenter.IP_ESX_DATA) > index:

                return SpringpathNetworkingSetup_VCenter.IP_ESX_DATA[index]

        return None

    def _getESXMgmtIPForHost(self, host):

        for index, host_name in enumerate(SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST):
            if self._hostMatchesName(host, host_name):
                return host_name

        return None

    def _hostMatchesName(self, host, host_name):

        if host.config and host.config.network and host.config.network.vnic:
            if [vnic for vnic in host.config.network.vnic if vnic.spec.ip.ipAddress == self._getHostByName(host_name)]:
                return True
            else:
                return False
        else:
            return False

    def _hostMatchesNameInEsxList(self, host):

        for esx_host in SpringpathNetworkingSetup_VCenter.ESX_HOST_LIST:

            if self._hostMatchesName(host, esx_host):
                return True

        return False

    def _getHostByName(self, ip_addr):

        try:
            return socket.gethostbyname(ip_addr)
        except socket.gaierror:
            return ip_addr

    # Gateway ARP-ping method to refresh gateway ARP cache
    # ----------------------------------------------------

    def _getIPFromGuest(self, stCtlVM, pg_name):
        """
        Returns the IP address for the given
        network from guest tools.
        """
        if stCtlVM.guest:
            for guest_nicinfo in stCtlVM.guest.net:

                if guest_nicinfo.network == pg_name and len(guest_nicinfo.ipAddress) > 0:
                    for ipaddress in guest_nicinfo.ipAddress:
                        if '.' in ipaddress:
                            return ipaddress

        logging.error("Unable to get IP for controller on pg: {0}.".format(pg_name))
        return None

    def _arp_pingControllerGateways(self):

        logging.debug("Pinging controller gateways.")

        # only ping gateway from
        # storage controller nodes
        # (not compute only nodes)
        hosts = self._getHosts()
        for host in hosts:

            if self._hostRoleIsStorage(host):
                stCtlVM = self._getControllerVMOnHost(host)

                # ensure controller
                # is powered on before
                # accessing.
                if stCtlVM.runtime.powerState != "poweredOn":
                   logging.info("Powering On the stCtlVM")
                   self._powerOnStCtlVM(stCtlVM, True, True)

                ip_mgmt = self._getIPFromGuest(stCtlVM, SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT)
                if ip_mgmt and SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT:
                    self._arp_pingGatewayFromController(stCtlVM,
                                                        SpringpathNetworkingSetup_VCenter.CTL_USER,
                                                        SpringpathNetworkingSetup_VCenter.CTL_PWD,
                                                        SpringpathNetworkingSetup_VCenter.IFC_MGMT,
                                                        ip_mgmt,
                                                        SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT)

                ip_data = self._getIPFromGuest(stCtlVM, SpringpathNetworkingSetup_VCenter.PG_CTL_DATA)
                if ip_data and SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA:
                    self._arp_pingGatewayFromController(stCtlVM,
                                                        SpringpathNetworkingSetup_VCenter.CTL_USER,
                                                        SpringpathNetworkingSetup_VCenter.CTL_PWD,
                                                        SpringpathNetworkingSetup_VCenter.IFC_DATA,
                                                        ip_data,
                                                        SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA)


    def _arp_pingValidateDuplicates(self):

        logging.debug("Verifying there are no dupliate IPs")

        # only ping IP from
        # storage controller nodes
        # (not compute only nodes)
        hosts = self._getHosts()
        for host in hosts:
            if self._hostRoleIsStorage(host):
                stCtlVM = self._getControllerVMOnHost(host)
                ip_index = self._getHostIndexInESXConfigList(host)

                # ensure controller
                # is powered on before
                # accessing.
                if stCtlVM.runtime.powerState != "poweredOn":
                   logging.info("Powering On the stCtlVM")
                   self._powerOnStCtlVM(stCtlVM, True, True)


                dupIPs = []
                ip_mgmt = self._getIPFromGuest(stCtlVM, SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT)
                if ip_mgmt != self._getHostByName(SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT[ip_index]):
                  err = self._arp_pingIPFromController(stCtlVM,
                                                      SpringpathNetworkingSetup_VCenter.CTL_USER,
                                                      SpringpathNetworkingSetup_VCenter.CTL_PWD,
                                                      SpringpathNetworkingSetup_VCenter.IFC_MGMT,
                                                      SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT[ip_index])
                  (dupIPs.append(err) if err is not None else [])

                else:
                  logging.debug("{} is already set on {}, skipping duplicate IP check".format(ip_mgmt, stCtlVM.name))

                ip_data = self._getIPFromGuest(stCtlVM, SpringpathNetworkingSetup_VCenter.PG_CTL_DATA)
                if ip_mgmt != self._getHostByName(SpringpathNetworkingSetup_VCenter.IP_CTL_DATA[ip_index]):
                  err = self._arp_pingIPFromController(stCtlVM,
                                                      SpringpathNetworkingSetup_VCenter.CTL_USER,
                                                      SpringpathNetworkingSetup_VCenter.CTL_PWD,
                                                      SpringpathNetworkingSetup_VCenter.IFC_DATA,
                                                      SpringpathNetworkingSetup_VCenter.IP_CTL_DATA[ip_index])
                  (dupIPs.append(err) if err is not None else [])

                else:
                  logging.debug("{} is already set on {}, skipping duplicate IP check".format(ip_data, stCtlVM.name))

                ip_esx_data = None
                vmks = host.configManager.networkSystem.networkConfig.vnic
                for vmk in vmks:
                    if vmk.portgroup == SpringpathNetworkingSetup_VCenter.PG_ESX_DATA:
                      ip_esx_data = vmk.spec.ip.ipAddress
                if ip_esx_data != self._getHostByName(SpringpathNetworkingSetup_VCenter.IP_ESX_DATA[ip_index]):
                  err = self._arp_pingIPFromController(stCtlVM,
                                                      SpringpathNetworkingSetup_VCenter.CTL_USER,
                                                      SpringpathNetworkingSetup_VCenter.CTL_PWD,
                                                      SpringpathNetworkingSetup_VCenter.IFC_DATA,
                                                      SpringpathNetworkingSetup_VCenter.IP_ESX_DATA[ip_index])
                  (dupIPs.append(err) if err is not None else [])
                else:
                  logging.debug("{} is already set on {}, skipping duplicate IP check".format(ip_esx_data, stCtlVM.name))

                if len(dupIPs) > 0:
                  raise Exception("{} is reachable.  Please check for duplicate IP addresses and retry.".format(", ".join(dupIPs)))


    def _arp_pingGatewayFromController(self, stCtlVM, user, password, ifc_name, address_ctl, address_gateway):

        logging.debug("Attempting to arp-ping gateway: {0} from controller: {1} using source address: {2}, eth ifc: {3}".format(address_gateway, stCtlVM.name, address_ctl, ifc_name))

        argstring = "-c 1 -I {0} -s {1} {2}".format(ifc_name, address_ctl, address_gateway)
        cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(programPath='/usr/bin/arping', arguments=argstring)

        processManager = self.si.content.guestOperationsManager.processManager
        self._startProgramInGuest(processManager, stCtlVM, user, password, cmdspec, SpringpathNetworkingSetup_VCenter.USER_CTL_PWD)


    def _arp_pingIPFromController(self, stCtlVM, user, password, ifc_name, dest_address):

        dest_address = self._getHostByName(dest_address)
        logging.debug("Attempting to arp-ping IP: {0} from controller: {1} eth ifc: {2}".format(dest_address, stCtlVM.name, ifc_name))

        argstring = "-q -f -D -c 3 -I {0} {1}".format(ifc_name, dest_address)
        cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(programPath='/usr/bin/arping', arguments=argstring)

        processManager = self.si.content.guestOperationsManager.processManager
        exitCode = self._startProgramInGuest(processManager, stCtlVM, user, password, cmdspec, SpringpathNetworkingSetup_VCenter.USER_CTL_PWD)

        if exitCode == 1:
          return dest_address

    # Host role discovery methods
    # ---------------------------------------------

    def _hostRoleIsStorage(self, host):
        """
        Returns true if host
        is a "storage node" type,
        else returns false.
        """
        return self._hostAtIndexRoleIsStorage(self._getHostIndexInESXConfigList(host))

    def _hostAtIndexRoleIsStorage(self, ip_index):
        """
        Returns true if host at given index
        is a "storage node" type, else returns false.
        """
        return self._getHostRole(SpringpathNetworkingSetup_VCenter.IP_ESX_MGMT[ip_index]) == SpringpathNetworkingSetup_VCenter.ROLE_TYPE_STORAGE

    def _getHostRole(self, esx_host_address):
        """
        Returns the hosts "role" type. If not
        specified, returns type "STORAGE"
        """
        esx_host_address_resolved = self._getHostByName(esx_host_address)
        if esx_host_address_resolved in SpringpathNetworkingSetup_VCenter.ESX_ROLE_MAP:
            return SpringpathNetworkingSetup_VCenter.ESX_ROLE_MAP[esx_host_address_resolved]
        else:
            return SpringpathNetworkingSetup_VCenter.ROLE_TYPE_STORAGE

    # Controller IP  and udev configuration methods
    # ---------------------------------------------

    def _setResetControllers(self):
        """
        Resets controller udev rules, IP and
        destroys controller vnics.
        """
        self._resetControllerIPs()

        if not (SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY == SpringpathNetworkingSetup_VCenter.HARDWARE_TYPE_INVENTORY_HX):
            self._destroyControllerVNICs()

    def _removeLineFromControllerFile(self, stCtlVM, user, password, filename, search):
        """
        Updates a file on the controller
        using guest tools.
        """
        logging.debug("Remove line in file {0} on controller {1} with search contents {2}.".format(filename, stCtlVM.name, search))

        # ensure controller
        # is powered on before
        # accessing.
        if stCtlVM.runtime.powerState != "poweredOn":
           logging.info("Powering On the stCtlVM")
           self._powerOnStCtlVM(stCtlVM, True, False)

        argstring = "-i '/" + search + "/d' " + filename
        cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(programPath='/bin/sed', arguments=argstring)

        processManager = self.si.content.guestOperationsManager.processManager
        self._startProgramInGuest(processManager, stCtlVM, user, password, cmdspec, SpringpathNetworkingSetup_VCenter.USER_CTL_PWD)

    def _updateControllerFile(self, stCtlVM, user, password, filename, contents, append=False, mode=0644):
        """
        Updates a file on the controller
        using guest tools.
        """
        logging.debug("Replacing or updating file {0} on controller {1} with contents {2}.".format(filename, stCtlVM.name, contents))

        # ensure controller
        # is powered on before
        # accessing.
        if stCtlVM.runtime.powerState != "poweredOn":
            logging.info("Powering On the stCtlVM")
            self._powerOnStCtlVM(stCtlVM, True, False)
        # if stCtlVM.guestHeartbeatStatus != "green":
        #     logging.info("Wait for heartbeat status to be green")
        #     self._waitForStCtlVMHeartBeatToTurnGreen(stCtlVM)
        indirection = '>'
        if append:
            indirection = '>>'

        argstring = '-e ' + '\'' + contents + '\'' + indirection + ' ' + filename
        cred = vim.vm.guest.NamePasswordAuthentication(username=user, password=password)
        cmdspec = vim.vm.guest.ProcessManager.ProgramSpec(programPath='/bin/echo', arguments=argstring)

        processManager = self.si.content.guestOperationsManager.processManager
        fileManager = self.si.content.guestOperationsManager.fileManager

        attr = vim.vm.guest.FileManager.PosixFileAttributes()
        attr.permissions = mode

        try:
            processManager.StartProgramInGuest(vm=stCtlVM, auth=cred, spec=cmdspec)
            time.sleep(1.0)
            fileManager.ChangeFileAttributes(vm=stCtlVM, auth=cred, guestFilePath=filename, fileAttributes=attr)
        except Exception:
            if SpringpathNetworkingSetup_VCenter.USER_CTL_PWD:
                logging.debug("Trying to login with user defined password")
                cred = vim.vm.guest.NamePasswordAuthentication(username=user, password=SpringpathNetworkingSetup_VCenter.USER_CTL_PWD)
                try:
                    processManager.StartProgramInGuest(vm=stCtlVM, auth=cred, spec=cmdspec)
                    time.sleep(1.0)
                    fileManager.ChangeFileAttributes(vm=stCtlVM, auth=cred, guestFilePath=filename, fileAttributes=attr)
                except Exception as e:
                    logging.exception('Failed: ' + str(e))
                    raise Exception("Failed to login controller VM" + str(e))

    def _resetControllerUDEVRules(self):
        """
        Resets contoller udev rules.
        """
        logging.debug("Resetting controller udev rules.")
        stCtlVMs = self._getControllerVMs()
        for stCtlVM in stCtlVMs:

            if not self._isControllerConfigured(stCtlVM):
                self._powerOnStCtlVM(stCtlVM, True, True)
                self._resetUDEVRules(stCtlVM,
                                     SpringpathNetworkingSetup_VCenter.CTL_USER,
                                     SpringpathNetworkingSetup_VCenter.CTL_PWD)

                logging.info("ResetControllerUDEVRules: Power cycling stCtlVM Name {0} ".format(stCtlVM.name))
                self._powerOffStCtlVM(stCtlVM)
                self._powerOnStCtlVM(stCtlVM, True, True)
            else:
                logging.debug("The controller {0} is already configured. Will not reset udev rules.".format(stCtlVM.name))

    def _isNic(self, device):
        return (isinstance(device, vim.vm.device.VirtualEthernetCard) and
                isinstance(device.backing,
                           vim.vm.device.VirtualEthernetCard.NetworkBackingInfo))

    def _getMacAddress(self, configInfo, nwName):
        """
        Finds the mac address of a vNIC connected to the given network
        """
        logging.debug("Finding the macaddress for %s" % nwName)
        macs = [device.macAddress for device in configInfo.hardware.device
                if self._isNic(device) and device.backing.deviceName == nwName]
        # Return None if not found, since we are not sure if all of the NICs are
        # connected at the time of this call, returning None is safer.
        if (len(macs) == 1):
            logging.debug("Found macaddress for %s %s" % (nwName, macs[0]))
            return macs[0]
        else:
            logging.error("Unable to find macaddress for %s" % nwName)
            logging.debug("VM Info %s " % configInfo)
            return None

    def _resetUDEVRules(self, stCtlVM, user, password):
        """
        Resets udev rules on contoller.
        """
        logging.debug("Resetting udev rules for controller {0}.".format(stCtlVM.name))

        mgmtIf = {'pg': SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                  'mac': None,
                  'ifname': SpringpathNetworkingSetup_VCenter.IFC_MGMT_NAME}
        dataIf = {'pg': SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                  'mac': None,
                  'ifname': SpringpathNetworkingSetup_VCenter.IFC_DATA_NAME}
        replIf = {'pg': SpringpathNetworkingSetup_VCenter.PG_CTL_REPL_NWK,
                  'mac': None,
                  'ifname': SpringpathNetworkingSetup_VCenter.IFC_CTL_REPL_NWK_NAME}

        if hasattr(SpringpathNetworkingSetup_VCenter, 'VSWITCH_CTL_REPL'):
            ifList = [mgmtIf, dataIf, replIf]
        else:
            ifList = [mgmtIf, dataIf]

        configInfo = stCtlVM.config

        content = """# This file has been auto-generated during Springpath controller deployment."""
        mac_str = """SUBSYSTEM=="net" ACTION=="add" ATTR{address}==\"%s\" ATTR{dev_id}=="0x0" ATTR{type}=="1" NAME=\"%s\""""

        for ifitem in ifList:
            logging.debug("Getting MAC address for :{} , ifName: {}".format(ifitem['pg'], ifitem['ifname']))
            mac = self._getMacAddress(configInfo, ifitem['pg'])
            if mac is not None:
                new_mac_str = mac_str % (mac, ifitem['ifname'])
                content += '\n' + new_mac_str
            else:
                logging.error("Got no MAC for Port Group: " + ifitem['pg'])
                raise Exception("Failed to get MAC address for Port Group: " + ifitem['pg'])

        logging.debug("Setting udev rules w/ content : " + content)

        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   '/etc/udev/rules.d/70-persistent-net.rules',
                                   content)
        self._outputStatusStep('network - reset controller udev rules',
                               SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                               stCtlVM.name,
                               SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_NODE,
                               stCtlVM.name)

    def _resetControllerIPs(self):
        """
        Resets contoller IP settings.
        """
        logging.debug("Resetting controller IP's.")

        # for each host, we get the controller and set it's IP
        hosts = self._getHosts()
        for host in hosts:

            if not self._isHostControllerConfigured(host):
                stCtlVM = self._getControllerVMOnHost(host)
                ip_index = self._getHostIndexInESXConfigList(host)

                if ip_index >= 0 and self._hostAtIndexRoleIsStorage(ip_index):
                    self._resetIP(stCtlVM,
                                  SpringpathNetworkingSetup_VCenter.CTL_USER,
                                  SpringpathNetworkingSetup_VCenter.CTL_PWD,
                                  ip_index)
                else:
                    logging.debug("The host {0} is not for storage. Will not reset controller IP.".format(host.name))
            else:
                logging.debug("The controller on host {0} is already configured. Will not reset IP.".format(host.name))

    def _resetIP(self, stCtlVM, user, password, ip_index):
        """
        Resets IP networking settings on contoller.
        """
        logging.debug("Resetting IP settings for controller {0}.".format(stCtlVM.name))

        # reset the '/etc/network/interfaces' file.
        self._resetNetworkInterfacesFile(stCtlVM,
                                         user,
                                         password)

        static_mgmt_set = False

        # reset the controller management eth interface.
        if SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT and \
                len(SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT) > ip_index and \
                len(SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT[ip_index]) > 0 and \
                SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_MGMT:

            logging.debug("Setting controller management IP to static.")
            self._setNetworkInterfaceStatic(stCtlVM,
                                            user,
                                            password,
                                            SpringpathNetworkingSetup_VCenter.IFC_MGMT,
                                            SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT[ip_index],
                                            SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_MGMT,
                                            SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_MGMT,
                                            100,
                                            SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                            SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST,
                                            None)
            static_mgmt_set = True
        else:

            logging.debug("Setting controller management IP to use DHCP.")
            self._setNetworkInterfaceDynamic(stCtlVM,
                                             user,
                                             password,
                                             SpringpathNetworkingSetup_VCenter.IFC_MGMT,
                                             SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                             SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST,
                                             None)

        # reset the controller data eth interface.
        if SpringpathNetworkingSetup_VCenter.IP_CTL_DATA and \
                len(SpringpathNetworkingSetup_VCenter.IP_CTL_DATA) > ip_index and \
                len(SpringpathNetworkingSetup_VCenter.IP_CTL_DATA[ip_index]) > 0 and \
                SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA:

            logging.debug("Setting controller data IP to static.")
            self._setNetworkInterfaceStatic(stCtlVM,
                                            user,
                                            password,
                                            SpringpathNetworkingSetup_VCenter.IFC_DATA,
                                            SpringpathNetworkingSetup_VCenter.IP_CTL_DATA[ip_index],
                                            SpringpathNetworkingSetup_VCenter.NET_MASK_CTL_DATA,
                                            SpringpathNetworkingSetup_VCenter.GATEWAY_CTL_DATA,
                                            101,
                                            SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                            SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST,
                                            SpringpathNetworkingSetup_VCenter.MTU_DATA)
        else:

            logging.debug("Setting controller data IP to use DHCP.")
            self._setNetworkInterfaceDynamic(stCtlVM,
                                             user,
                                             password,
                                             SpringpathNetworkingSetup_VCenter.IFC_DATA,
                                             SpringpathNetworkingSetup_VCenter.DNS_HOST_LIST,
                                             SpringpathNetworkingSetup_VCenter.DNS_SEARCH_LIST,
                                             SpringpathNetworkingSetup_VCenter.MTU_DATA)

        self._setHostName(stCtlVM,
                          user,
                          password,
                          SpringpathNetworkingSetup_VCenter.IP_CTL_MGMT[ip_index] if static_mgmt_set else None)

        self._outputStatusStep('network - reset IP settings',
                               SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                               stCtlVM.name,
                               SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_NODE,
                               stCtlVM.name)

    def _setHostName(self, stCtlVM, user, password, address):
        """
        Resets /etc/hostname file on contoller.
        """
        logging.debug("Resetting /etc/hostname file on controller {0} using address {1}.".format(stCtlVM.name, address))

        # lookup hostname from
        # DNS if possible
        # else randomly generate
        hostname = None
        ip_address = None
        if address:
            try:
                # to avoid having to do
                # forward look-up, we do a
                # reverse look-up and from
                # there determine if we have an IP or
                # host name. Only then do we try
                # a forward look-up if needed.
                ip_address = socket.gethostbyname(address)
                if ip_address == address:
                    addr_info = socket.gethostbyaddr(address)
                    if len(addr_info) > 0:
                        hostname = addr_info[0]
                else:
                    hostname = address

            except socket.gaierror:
                logging.error("Failed to lookup hostname on controller {0} using address {1}. Name or service not known.".format(stCtlVM.name, address))
            except socket.herror:
                logging.error("Failed to lookup hostname on controller {0} using address {1}. Unknown host.".format(stCtlVM.name, address))

        # update /etc/hosts file here for lookup of generated name (use either static address or 127.0.1.1)
        hostname_ip_address = ip_address if ip_address else "127.0.1.1"

        # always clear entry from /etc/hosts in case was added from previous deployment and hostname changed
        self._removeLineFromControllerFile(stCtlVM,
                                           user,
                                           password,
                                           '/etc/hosts',
                                           SpringpathNetworkingSetup_VCenter.HOSTNAME_COMMENT)

        if not hostname:
            logging.debug("Could not lookup host name from controller address. Setting host name to random string and updating /etc/hosts file.")
            hostname = 'SpringpathController' + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            self._updateControllerFile(stCtlVM,
                                       user,
                                       password,
                                       '/etc/hosts',
                                       hostname_ip_address + ' ' + hostname + ' ' + SpringpathNetworkingSetup_VCenter.HOSTNAME_COMMENT + '\n',
                                       True)

        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   '/etc/hostname',
                                   hostname)

    def _resetNetworkInterfacesFile(self, stCtlVM, user, password):
        """
        Resets network interface file.
        """
        logging.debug("Resetting network IP rules for controller {0}.".format(stCtlVM.name))

        content = "# This file has been auto-generated during Springpath Controller setup.\n\n" + \
                  "# The loopback network interface\n" + \
                  "auto lo\n" + \
                  "iface lo inet loopback\n\n" + \
                  "source /etc/network/eth0.interface\n" + \
                  "source /etc/network/eth1.interface\n"
        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   '/etc/network/interfaces',
                                   content)

        rename_interfaces = r"""#!/bin/sh
test -L "/sys/class/net/mgmt-if" && ip link set mgmt-if name eth0
test -L "/sys/class/net/data-if" && ip link set data-if name eth1
test -L "/sys/class/net/repl-if" && ip link set repl-if name eth2
exit 0"""
        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   '/etc/network/if-pre-up.d/rename-interfaces',
                                   rename_interfaces,
                                   mode=0755)

    def _setNetworkInterfaceDynamic(self, stCtlVM, user, password, ifc_name, dns_host_list=None, dns_search_list=None, mtu=None):
        """
        Sets controller network interface
        with dynamic IP.
        """
        logging.debug("Resetting network IP rules for controller {0} on interface {1} to DHCP.".format(stCtlVM.name, ifc_name))

        if SpringpathNetworkingSetup_VCenter.FACTORY_MODE and ifc_name == 'eth1':
            content = "# This file has been auto-generated during Springpath Controller setup.\n\n" + \
                      "manual " + ifc_name + "\n" + \
                      "iface " + ifc_name + " inet dhcp\n"
        else:
            content = "# This file has been auto-generated during Springpath Controller setup.\n\n" + \
                      "auto " + ifc_name + "\n" + \
                      "iface " + ifc_name + " inet dhcp\n"

        if dns_host_list and len(dns_host_list) > 0:
            content = content + "dns-nameservers " + ' '.join(dns_host_list) + "\n"

        if dns_search_list and len(dns_search_list) > 0:
            content = content + "dns-search " + ' '.join(dns_search_list) + "\n"

        if mtu:
            logging.debug("Setting mtu size in controller of: {}.".format(mtu))
            content = content + "mtu " + str(mtu) + "\n"

        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   "/etc/network/" + ifc_name + ".interface",
                                   content)

    def _setNetworkInterfaceStatic(self, stCtlVM, user, password, ifc_name, address, netmask, gateway, metric=None, dns_host_list=None, dns_search_list=None, mtu=None):
        """
        Sets controller network interface
        with static IP.
        """
        logging.debug("Resetting network IP rules for controller {0} on interface {1} to static.".format(stCtlVM.name, ifc_name))

        content = "# This file has been auto-generated during Springpath Controller setup.\n\n" + \
                  "auto " + ifc_name + "\n" + \
                  "iface " + ifc_name + " inet static\n" + \
                  "address " + self._getHostByName(address) + "\n" + \
                  "netmask " + netmask + "\n"

        if gateway:
            content = content + "gateway " + self._getHostByName(gateway) + "\n"

        if metric:
            content = content + "metric " + str(metric) + "\n"

        if dns_host_list and len(dns_host_list) > 0:
            content = content + "dns-nameservers " + ' '.join(dns_host_list) + "\n"

        if dns_search_list and len(dns_search_list) > 0:
            content = content + "dns-search " + ' '.join(dns_search_list) + "\n"

        if mtu:
            logging.debug("Setting mtu size in controller of: {}.".format(mtu))
            content = content + "mtu " + str(mtu) + "\n"

        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   "/etc/network/" + ifc_name + ".interface",
                                   content)

        logging.debug("Emptying resolv.conf entries")
        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   "/etc/resolv.conf",
                                   "#deleted default entries by installer")
        logging.debug("Emptying resolv.conf.d/original entries")
        self._updateControllerFile(stCtlVM,
                                   user,
                                   password,
                                   "/etc/resolvconf/resolv.conf.d/original",
                                   "#deleted default entries by installer")

    # validation and status output methods
    # -----------------------------------

    # Example encoding of progress step with fault
    # {"1":{"str":"$STEPNAME"},"2":{"i32":$STEPSTATE},"4":{"rec":{"1":{"str":"$ENTITYID"},"2":{"i32":$ENTITYTYPE}}},"5":{"rec":{"1":{"i32":$FAULTCODE},"4":{"str":"$FAULTMESG"}}}}

    # Example encoding of progress step with success
    # {"1":{"str":"abc"},"2":{"i32":1},"3":{"str":"pqr"},"4":{"rec":{"1":{"str":"myid"},"2":{"i32":3}}}}
    def _outputStatusStep(self, step_name, step_state, entityid, entity_type, entity_name, fault_code=None, fault_msg="Unknown Error"):
        """
        Handles output needed by
        external framework.
        """
        step_exception_json = ''
        if fault_code:
            step_exception_json = ',\"5\":{\"rec\":{\"1\":{\"i32\":' + str(fault_code) + '},\"4\":{\"str\":\"' + fault_msg + '\"}}}'

        step_json = '{\"1\":{\"str\":\"' + step_name + '\"},\"2\":{\"i32\":' + str(step_state) + \
                    '},\"4\":{\"rec\":{\"1\":{\"str\":\"' + str(entityid) + \
                    '\"},\"2\":{\"i32\":' + str(entity_type) + \
                    '},\"3\":{\"str\":\"' + str(entity_name) + '\"}}}' + step_exception_json + '}'

        logging.debug("Outputting status step: {0}".format(step_json))
        print step_json

    def handleError(self, fault_code=None, fault_msg="Unknown Error", exit_script=True):
        """
        Handles error by outputting
        status step, logging the error
        and optionally exiting the script.
        """
        logging.error("Error occurred. Fault code: {0}, fault message: {1}, exiting script: {2}".format(fault_code, fault_msg, exit_script))
        sys.stderr.write(fault_msg)

        if exit_script:
            sys.exit(1)

    def _validateSetup(self):

        # TODO More complete validation here...
        # Can we access the controller and ESXi management IPs (e.g. SSH)?
        # Can ESXi ping the controller from the data interface?
        # SSH to ESXi mgmt and ping controller from data interface
        # SSH to controller mgmt and ping ESXi from data interface

        logging.debug("Validating network setup")
        logging.debug("Checking if have valid stCtl IP address on Springpath controller management network.")
        stCtlVMIP = self.executeScriptWithResponse("/opt/springpath/support/getstctlvmip.sh",
                                                   SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT)

        logging.debug("Found stCtl IP: " + stCtlVMIP)
        if not isValidIP4Address(stCtlVMIP):
            logging.error("WARNING: The stCtl VM has an invalid IP address!!!")
        else:
            logging.debug("stCtl IP: " + stCtlVMIP + " is valid.")

    def _executeHostCommand(self, host, user, pwd, command):
        """
        Executes remote SSH command on host with user/pwd for auth.
        """
        logging.debug("Executing SSH command " + command + " on host (using password): " + host)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=pwd, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = ssh.exec_command(command)
        status_code = stdout.channel.recv_exit_status()
        logging.debug("Executing SSH command out: " + stdout.read())
        ssh.close()
        return status_code

    def _checkServiceOnHost(self, host, service):
        count = 0
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if service == 'ssh':
            while count < SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
                try:
                    if count > 0:
                        logging.debug("Connecting to host : " + host + " again at SSH port 22")
                    else:
                        logging.debug("Connecting to host : " + host + " at SSH port 22")

                    s.connect((host, 22))
                    logging.debug("Success: Host {} SSH port 22 ".format(host))
                    s.close()
                    return True
                except socket.error as e:
                    logging.debug("Error on connect: %s" % e)
                    time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
                    count = count + 1
                    if count > SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
                        logging.debug("ERROR: Host " + host + " is not online after attempts:" + int(count))
                        s.close()
                        return False

    def _copyFileToRemoteHost(self, host, user, pwd, localfile, remotefile):

        cmd = "sshpass -p \'{}\' scp -o StrictHostKeyChecking=no {} {}@{}:{}".format(pwd, localfile, user, host, remotefile)

        cmd_filtered = re.sub(r'-p .+\'', r'xxxxxxxx', cmd)
        logging.debug("Copying vswitch rename script to host. Cmd: " + cmd_filtered)
        return os.system(cmd)

    def _waitForHostVCConnected(self, host):

        logging.debug("Waiting for ESXi host {} to be connected. Current connection state: {}".format(host.name, host.runtime.connectionState))

        count = 1
        while host.runtime.connectionState != "connected" and count < SpringpathNetworkingSetup_VCenter.MAX_RETRIES:
            logging.debug("Waiting for ESXi host {} to be online and connected. Attempt: {}. Current connection state: {}".format(host.name, count, host.runtime.connectionState))
            time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_TIME)
            count = count + 1

    def _renameDefaultMgmtVswitch(self, host, user, pwd, switch_old_name, switch_new_name):
        '''
        ESXi install creates vSwitch0 standard vswitch. HyperFlex mandates
        creating vswitches with standard names. So rename vSwitch0 to vswitch-hx-inband-mgmt
        '''
        esx_mgmt_ip = self._getESXMgmtIPForHost(host)

        VSWITCH_SCRIPT_REMOTE_LOCATION = "/tmp"
        cmd = "cp {} {}".format(SpringpathNetworkingSetup_VCenter.VSWITCH_RENAME_SCRIPT, VSWITCH_SCRIPT_REMOTE_LOCATION)

        retval = self._copyFileToRemoteHost(esx_mgmt_ip, user, pwd,
                                            SpringpathNetworkingSetup_VCenter.VSWITCH_RENAME_SCRIPT, VSWITCH_SCRIPT_REMOTE_LOCATION)
        if retval != 0:
            logging.error("Failed to copy vswitch rename script to host: {}, retval: {}".format(esx_mgmt_ip, retval))
            raise Exception("Failed to copy vswitch rename script to host: {}, retval: {}".format(esx_mgmt_ip, retval))

        # Rename script usage is as follows:
        # vswitch_config.sh <old-vswitch-name> <new-vswitch-name>
        # If omitted, defaults to "vSwitch0" and "vswitch-hx-inband-mgmt" respectively
        cmd = "{}/{} {} {}".format(VSWITCH_SCRIPT_REMOTE_LOCATION,
                                   os.path.basename(SpringpathNetworkingSetup_VCenter.VSWITCH_RENAME_SCRIPT),
                                   switch_old_name,
                                   switch_new_name)

        retval = self._executeHostCommand(esx_mgmt_ip, user, pwd, cmd)
        if retval != 0:
            logging.error("Failed to execute remote vswitch config script on host: {}, retval: {}".format(esx_mgmt_ip, retval))
            raise Exception("Failed to execute remote vswitch config script on host: {}, retval: {}".format(esx_mgmt_ip, retval))

        # Wait for host to be online
        # sleep for few seconds before retrying with SSH port checks

        logging.info("Wait for host {} to be online...".format(esx_mgmt_ip))
        time.sleep(SpringpathNetworkingSetup_VCenter.WAIT_FOR_REBOOT)
        self._waitForHostVCConnected(host)

        return True

    def _configureReplicationPG_Standard(self, switch_name, pg_name, vnic_label, vnic_summary, vlanId, attachController=True):
        logging.debug("Configuring standard replication port group: {0} on switch: {1}".format(pg_name, switch_name))
        # power off all controllers if attach is being done
        if attachController:
            self._powerOffControllers()

        hosts = self._getHosts()
        for host in hosts:
            # set PG on correct switch, if not there already.
            self._setPgOnSwitch_Standard(host, switch_name, pg_name, vlanId)

            if attachController:
                # attach controller to PG
                self._attachControllersToReplicationNwk(host,
                                                       switch_name,
                                                       pg_name,
                                                       vnic_label,
                                                       vnic_summary)

            self._outputStatusStep('network - setup host controller replication port group',
                                   SpringpathNetworkingSetup_VCenter.STEP_STATE_SUCCEEDED,
                                   host.name,
                                   SpringpathNetworkingSetup_VCenter.ENTITY_TYPE_VIRTNODE,
                                   host.name)

    def _attachControllersToReplicationNwk(self, host, switch_name, pg_name, label, summary):
        '''
        Attaches controller to Replication Standard Port Group on a specified host
        '''
        if not self._isHostControllerConfigured(host):
            logging.debug("Adding controller to standard replication port group: {0} on switch: {1} on host: {2}".format(pg_name, switch_name, host.name))

            pg = self._getStandardPortGroupByName(host, pg_name)
	    if not pg:
                logging.error("Unable to attach controller to standard replication port group. Port group: {0} not found on host {1}.".format(pg_name, host.name))
                return

            stCtlVM = self._getControllerVMOnHost(host)
            if not stCtlVM:
                logging.error("Unable to attach controller to standard replication port group. Controller not found on host {0}.".format(host.name))
                return

            netaddspec = self._getStorvisorDataNetworkAddSpec(switch_name, pg_name, label, summary, False, False)
            self._attachControllerToPG(stCtlVM, netaddspec, pg_name, pg)
        else:
            logging.debug("The controller on host {0} is already configured. Will not attach to port group {1}.".format(host.name, pg_name))

    def _reconfigureVirtualEthernetDevices(self):
       logging.debug("Invoking _reconfigureVirtualEthernetDevices...")
       hosts = self._getHosts()
       for host in hosts:
          self._reconfigureVnic(host, SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                      SpringpathNetworkingSetup_VCenter.PG_CTL_MGMT,
                                      SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_MGMT,
                                      SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_MGMT)

          self._reconfigureVnic(host, SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_DATA,
                                      SpringpathNetworkingSetup_VCenter.PG_CTL_DATA,
                                      SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_DATA,
                                      SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_DATA)

          self._reconfigureVnic(host, SpringpathNetworkingSetup_VCenter.VSWITCH_CTL_MGMT,
                                      SpringpathNetworkingSetup_VCenter.PG_CTL_REPL_NWK,
                                      SpringpathNetworkingSetup_VCenter.VNIC_LABEL_CTL_REPL_NWK,
                                      SpringpathNetworkingSetup_VCenter.VNIC_SUMMARY_CTL_REPL_NWK)

    def _reconfigureVnic(self, host, switch_name, pg_name, label, summary):
       '''
       Reconfigure VirtualEthernet Devices on controller VM
       '''
       if not self._isHostControllerConfigured(host):
            logging.debug("Adding controller to standard port group: {0} on host: {1}".format(pg_name, host.name))

            pg = self._getStandardPortGroupByName(host, pg_name)
	    if not pg:
                logging.error("Unable to attach controller to standard port group. Port group: {0} not found on host {1}.".format(pg_name, host.name))
                return

            stCtlVM = self._getControllerVMOnHost(host)
            if not stCtlVM:
                logging.error("Unable to attach controller to standard port group. Controller not found on host {0}.".format(host.name))
                return

            logging.debug("Finding the VirtualEthernetDevice for %s" % pg_name)
            devices = [device for device in stCtlVM.config.hardware.device
                if self._isNic(device) and device.backing.deviceName == pg_name]

            if devices is None:
               logging.error("Unable to find the vNIC configured for standard port group: {0} not found on host {1}.".format(pg_name, host.name))
               raise Exception('Reconfiguring VNIC failed')

            logging.debug("Found the VirtualEthernet for {0}".format(devices))

            if pg_name == SpringpathNetworkingSetup_VCenter.PG_CTL_DATA:
                netaddspec = self._getStorvisorDataNetworkAddSpec(switch_name, pg_name,
                                                                  label, summary,
                                                                  True, True,
                                                                  operationType = "edit")
            else:
                netaddspec = self._getStorvisorMgmtNetworkAddSpec(switch_name, pg_name, label,
                                                                  summary,
                                                                  True, True,
                                                                  operationType = 'edit')

            netaddspec.device = devices[0]
            netaddspec.device.connectable = self._getStorvisorVirtualDeviceConnectInfo(True, True)

            self._reconfigController(stCtlVM, [netaddspec])
       else:
            logging.debug("ReconfigureVnic: The controller on host {0} is already configured. Will not attach to port group {1}.".format(host.name, pg_name))


def main():

    try:
        ssl._create_default_https_context = ssl._create_unverified_context
    except:
        pass

    net_setup = SpringpathNetworkingSetup_VCenter()
    net_setup.configureNetworking()
    sys.exit(0)

if __name__ == "__main__":
    main()
