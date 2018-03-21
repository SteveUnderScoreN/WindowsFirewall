<#
.Synopsis
   A script to create/update the firewall settings in a group policy object
.DESCRIPTION
   This script is from the repository https://github.com/SteveUnderScoreN/WindowsFirewall/ and is used together with a partially configured group policy object in a backup folder
   to create/update the firewall settings in a group policy object. These partially configured backups can be downloaded from the repository.
   There are arrays of domain resources which can be configured to create very specific firewall rules specific to the enterprise environment.
   The group policy management tools need to be installed on the computer running this script and it needs access to the DNS and AD infrastructure.
   The following 'Predefined set of computers' values are supported;
   'LocalSubnet'
   'DNS'
   'DHCP'
   'DefaultGateway'
   'Internet'
   'Intranet'
.VERSION
    0.7.0
.CHANGELOG
    Initial release
.EXAMPLE
   $ProxyServers = '2a02:cc9:7732:5500::1','fd4e:eaa9:897b::1','172.19.110.1'
.EXAMPLE
   $ProxyServers = 'proxy.mydomain.local','proxy2','proxy-server3'
.EXAMPLE
   $ProxyServers = '10.10.10.0/24','10.10.11.100-10.10.11.149'
#>

$SourceGPOBackupId = '{c69d83c5-1636-4ad7-b632-1f9b6963054e}'
$TargetGPOName = 'SN-Server Role - Remote Administration firewall Baseline'
$PathToGPOBackups = 'C:\Temp\SN-GPO'
$DomainName = $env:USERDNSDOMAIN
# Version 0.7.0 domain resources
$DomainControllers = '127.0.0.1','SERVERNAME'
$ProxyServerPorts = '8080'
$ProxyServers = 'LocalSubnet','Intranet'
$DNSServers = $DomainControllers # Specify these if you do not have DNS on each domain controller or you have additional DNS servers
$CRLServers = 'LocalSubnet','Intranet'
$WPAD_PACFileServers = 'LocalSubnet','Intranet'
$TierXManagementServers = 'LocalSubnet','Intranet' # These are used in tier X firewall baselines to define which computers can manage the device at a particular tier
$SQLServers = '127.0.0.4'
$WebServers = 'LocalSubnet','Intranet'
$FileServers = 'LocalSubnet','Intranet'
$KeyManagementServers = 'LocalSubnet','Intranet'
$BackupServers = '127.0.0.1'
$ClusteredNodesAndManagementAddresses = 'LocalSubnet','Intranet'
$ExternalVPNEndpoints = '127.0.0.2 -  127.0.0.3' # This is the externally resolvable IPSec hostname or address
$DirectAccessServers = '127.0.0.128/25' # This is the externally resolvable hostname or address of the DirectAccess IPHTTPS endpoint
$TrustedDHCPSubnets = 'Any' # This is client enterprise subnets and includes subnets issued by the VPN server, 'Predefined set of computers' cannot be used here
# END of version 0.7.0 domain resources

$Resources = 'DomainControllers','ProxyServers','DNSServers','CRLServers','WPAD_PACFileServers','TierXManagementServers','SQLServers','WebServers','FileServers','KeyManagementServers','BackupServers','ClusteredNodesAndManagementAddresses','ExternalVPNEndpoints','DirectAccessServers','TrustedDHCPSubnets'

function AttemptResolveDNSNAME ($Name)
{
    try
    {
        $Addresses += (Resolve-DnsName $Name -ErrorAction Stop).IPAddress
    }
    catch
    {
        Write-warning "The hostname $Name could not be resolved, check connectivity to the DNS infrastructure and ensure there is a valid host record for $Name."
    }
}

if (!(Test-Path "$PathToGPOBackups\manifest.xml" -ErrorAction SilentlyContinue))
{
    Write-Warning "The GPO backups cannot be found, please ensure the backup zip file has been downloaded and extracted to $PathToGPOBackups"
    break
}

foreach ($Resource in $Resources)
{
    $Addresses = @()
    $Names = (Get-Variable -Name $Resource).Value
    foreach ($Name in $Names.replace(" ",""))
    {
        switch -Wildcard ($Name)
        {
            "*/*"           {
                                $Addresses += $Name
                                break
                            }
            "LocalSubnet"   {
                                $Addresses += $Name
                                break
                            }
            "Intranet"      {
                                $Addresses += $Name
                                break
                            }
            "DNS"           {
                                $Addresses += $Name
                                break
                            }
            "DHCP"          {
                                $Addresses += $Name
                                break
                            }
            "DefaultGateway"{
                                $Addresses += $Name
                                break
                            }
            "Internet"      {
                                $Addresses += $Name
                                break
                            }
            "Any"           {
                                $Addresses += $Name
                                break
                            }
            "*-*"           {
                                try
                                {
                                    if ([ipaddress]$Name.Split("-")[0] -and [ipaddress]$Name.Split("-")[1])
                                    {
                                        $Addresses += $Name
                                    }
                                }
                                catch [Management.Automation.PSInvalidCastException]
                                {
                                    . AttemptResolveDNSNAME $Name

                                }
                            }
            default         {
                                try
                                {
                                    if ([ipaddress]$Name)
                                    {
                                        $Addresses += $Name
                                    }
                                }
                                catch [Management.Automation.PSInvalidCastException]
                                {
                                    . AttemptResolveDNSNAME $Name
                                }
                            }
        }
    }
    Set-Variable -Name $Resource -Value $Addresses
}

if (!(Get-GPO -DisplayName $TargetGPOName  -ErrorAction SilentlyContinue))
{
    Import-GPO -BackupId $SourceGPOBackupId -Path $PathToGPOBackups -TargetName $TargetGPOName -CreateIfNeeded -ErrorAction Stop
    $InboundSQLServersRules = 
    '{06366F05-FDB5-47B3-AD53-A1B3E3811DFC}'

    $OutboundProxyServersRules = 
    '{1E5D5774-1CD4-4468-A3F9-AFBB6FAFE3F9}',
    '{9D26817C-3792-482E-8173-39995E1E4821}',
    '{4B40B570-31A2-4315-9186-E65AEED0347B}'

    $OutboundDomainControllersRules = 
    '{2AAE42BB-84E7-47D5-9E0D-1C6DCD2F9719}',
    '{19FD81F5-2520-4378-B492-E9A68816F4C9}',
    '{B500642B-2DDB-4DE6-8A6D-2569061FBB7B}',
    '{BD9C4BB0-33EA-491B-9C93-480E5814A984}',
    '{69AA8E32-0D08-4EE2-95FA-01B94F7249FA}',
    '{82DDA6BB-674A-47DC-A0A0-1890B805DA0F}',
    '{C2D8E478-3BFD-4BDE-ACAF-4FE25C4FE553}',
    '{87D48CC0-21AD-4DD4-8931-A44134C19DF3}',
    '{7BAD2B46-F43F-4C1B-AF95-EE67F609657E}',
    '{CE9CB7EC-5713-4F83-9CEC-BC89080557A0}',
    '{3FD6B54C-9499-4728-9CE7-7DEBD83EC1A5}',
    '{A164981A-675A-4A6B-B194-DC5F22988094}',
    '{F6880716-35C0-4484-9CF5-1CB615A7D16A}',
    '{B37078CD-00F6-4E4E-BF2C-57005831B642}',
    '{F1E8A5D9-0B28-4FE7-9323-494BC9469129}',
    '{32A0C4AD-8994-4DEE-810F-D40AAC5C682D}',
    '{D8C6D330-F81F-4C42-9357-B59B223424DC}',
    '{7C16F956-F3D3-4D39-BF3B-5D0CA03D0F6C}'

    $OutboundWebServersRules = 
    '{769B7312-4575-461E-9AF0-FFA46B40D84D}',
    '{AE651744-34A4-4976-ADFC-54D20FEC9BDF}'

    $OutboundSQLServersRules = 
    '{B11CC9D5-9DDA-4021-9048-B7E21B1230AC}',
    '{9CD6A215-CEFE-4D32-9542-5753A069FA76}'

    $OutboundClusteredNodesAndManagementAddressesRules = 
    '{B0D25960-B3D4-415C-A426-E3F38F39B33E}',
    '{AC3A5E65-E04D-44E2-A5CF-4A59521FCC6D}'

    $GPOSession = Open-NetGPO -PolicyStore "$DomainName\$TargetGPOName"
    foreach ($InboundSQLServersRule in $InboundSQLServersRules)
    {
        Set-NetFirewallRule -Name $InboundSQLServersRule -GPOSession $GPOSession -RemoteAddress $SQLServers
    }
    foreach ($OutboundSQLServersRule in $OutboundSQLServersRules)
    {
        Set-NetFirewallRule -Name $OutboundSQLServersRule -GPOSession $GPOSession -RemoteAddress $SQLServers
    }
    foreach ($OutboundProxyServersRule in $OutboundProxyServersRules)
    {
        Set-NetFirewallRule -Name $OutboundProxyServersRule -GPOSession $GPOSession -RemoteAddress $ProxyServers -RemotePort $ProxyServerPorts
    }
    foreach ($OutboundDomainControllersRule in $OutboundDomainControllersRules)
    {
        Set-NetFirewallRule -Name $OutboundDomainControllersRule -GPOSession $GPOSession -RemoteAddress $DomainControllers
    }
    foreach ($OutboundWebServersRule in $OutboundWebServersRules)
    {
        Set-NetFirewallRule -Name $OutboundWebServersRule -GPOSession $GPOSession -RemoteAddress $WebServers
    }
    foreach ($OutboundClusteredNodesAndManagementAddressesRule in $OutboundClusteredNodesAndManagementAddressesRules)
    {
        Set-NetFirewallRule -Name $OutboundClusteredNodesAndManagementAddressesRule -GPOSession $GPOSession -RemoteAddress $ClusteredNodesAndManagementAddresses
    }
    Save-NetGPO -GPOSession $GPOSession
}
else
{
    Write-Warning "The policy `"$TargetGPOName`" already exists and no updates are available for this baseline"
    Break
}
