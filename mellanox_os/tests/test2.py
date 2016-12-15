from cloudshell.shell.core.context import ResourceCommandContext, ConnectivityContext

import mellanox_os.src.driver

d = mellanox_os.src.driver.MellanoxOsDriver()

context = ResourceCommandContext()

ssh, channel, _ = d._connect(context)

print d._ssh_command(context, ssh, channel, 'show version', ' # ')
print d._ssh_command(context, ssh, channel, 'show interfaces', ' # ')
