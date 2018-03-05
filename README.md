# WindowsFirewall
A repository containing PowerShell scripts and firewall policies to configure Windows clients and servers including protocol, port,IP and application. These policies can be used with privileged access workstations as documented here - https://docs.microsoft.com/en-gb/windows-server/identity/securing-privileged-access/privileged-access-workstations.
Over the coming days I will add 3 PowerShell scripts and upload 3 group policy objects, the scripts can be populated with the IP addresses of your domain resources which will create very specific firewall rules for your domain.
These policies should not be modified outside the scripts provided, domain specific policies should be created that sit above these baselines in the group policy link order. These domain specific policies (e.g. Domain Firewall, Tier 0 Devices Firewall, Server Role - Remote Administration Firewall) can have additional firewall allow or block rules. A block rule will override any rule in the baseline.
These baselines must be above the any computer baseline provided by Microsoft (e.g. SCM Windows 10 TH2 - Computer).
# Domain Firewall Baseline
This policy is designed to sit at the root of the domain and contains rules that apply to all domain members. If policy inheritance is blocked on the OU this policy needs to be added to that OU and should be last in the link order
# Tier X Devices Firewall Baseline
The Tier X script will create a policy that has rules for client devices and rules defining which IP addresses are allowed to manage the tier x device.
# Server Role - Remote Administration Firewall Baseline
This policy contains rules that allow an administration server or privileged access workstation to manage resources in the domain. The outbound rules can include multiple tiers and each tier devices will have rules that either allow or deny the connection
