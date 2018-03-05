# WindowsFirewall
A repository containing PowerShell scripts and firewall policies to configure Windows clients and servers including protocol, port, IP and application. These policies can be used with privileged access workstations as documented [here] (https://docs.microsoft.com/en-gb/windows-server/identity/securing-privileged-access/privileged-access-workstations).
The scripts can be populated with the IP addresses of your domain resources which will create very specific firewall rules for your domain.  
These policies should not be modified outside the scripts provided, domain specific policies should be created that sit above these baselines in the group policy link order. These domain specific policies (e.g. Domain Firewall, Tier 0 Devices Firewall, Server Role - Remote Administration Firewall) can have additional firewall allow or block rules. A block rule will override any rule in the baseline.
These baselines must be above the any computer baseline provided by Microsoft (e.g. SCM Windows 10 TH2 - Computer).  
The domain firewall baseline enables auditing of denied connection attempts within the security event log (ID 5157), the tier x device firewall baseline enables auditing of denied and permitted connections (ID 5156). Permitted and denied connections are essential forensic evidence and should be archived. Logs should be set to automatically backup when full, a scheduled task can be created on event ID 1105 which runs a script to zip the logs locally. These logs can then be harvested by a central server and stored or imported into the event management system.
## Domain Firewall Baseline
This policy is designed to sit at the root of the domain and contains rules that apply to all domain members. If policy inheritance is blocked on the device OU (as per PAW documentation) this policy needs to be added to the device OU and should be last in the link order.
## Tier X Devices Firewall Baseline
The Tier X script will create a policy that has rules for client devices and rules defining which IP addresses are allowed to manage the tier device.
## Server Role - Remote Administration Firewall Baseline
This policy contains rules that allow an administration server or privileged access workstation to manage resources in the domain. The outbound rules can include multiple tiers and each tier devices will have rules that either allow or deny the connection.

## Notes
### Supported
 - DirectAccess  
 - IPSEC VPN  
 - IPv6  
 - Windows 10  
 - Windows Server 2012 R2/2016  
 - Privileged access workstations  
'Predefined set of computers' is supported and the following applies;  
  'Local Subnet'  includes and connected IP range for which an IP address has been assigned  
  'Intranet'      includes and IP subnet that have been added to 'Sites and Services (dssite.msc)', these are harvested by the IP helper  
                  service and can be seen in the following registry key;  
                  HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ADHarvest  
  'DNS Servers    Does not include the IPv6 addresses of DNS servers  
  'Internet'      Is everything that isn't in the ADHarvest registry key  
### Not supported
 - NetBIOS  
 - WINS  
### Other
NTLM should be blocked forcing mutual authentication via Kerberos, if there is a requirements for NTLM authentication to a server it should be whitelisted in the NTLM exceptions within a group policy object.  
Some SVCHOST services do not honour the firewall settings, there are some temporary SVCHOST rules to cover these that may be refined at a later date.
