from cloudshell.shell.core.context import ResourceCommandContext, ConnectivityContext

import driver

d = driver.MellanoxOsDriver()

context = ResourceCommandContext()

ssh, channel, _ = d._connect(context)

print d._ssh_command(context, ssh, channel, 'show version', ' # ')
print d._ssh_command(context, ssh, channel, 'show interfaces', ' # ')
