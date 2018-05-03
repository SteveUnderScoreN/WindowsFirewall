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

$SourceGPOBackupId = '{7a3ae19b-11be-4cf7-a078-15c03a897e90}' # Do not modify this
$TargetGPOName = 'SN-Tier X Firewall Baseline'
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
    $InboundTierXManagementServersRules = 
    '{B29AA00C-5CD1-4C86-B9F6-B24B3A652988}',
    '{B8DD676D-8553-4980-95FE-494171CA9353}',
    '{FC8B55E2-C3D2-4636-B6DA-5AF13F451B54}',
    '{C4476117-3D16-44E4-A89E-802D59429288}',
    '{973282B3-4D8A-4D77-8966-86C8A69A9D19}',
    '{0B7482C6-20B3-4F22-9F5D-4CBE0E41C4D5}',
    '{6E3791DE-11FA-4DEB-A87F-C895EB2C504A}',
    '{6F40346F-5FD5-467E-8C6C-B2ADD07DF5F9}',
    '{FF84E440-7B62-416B-B292-E22E757A2CCD}',
    '{CF2FC131-9A7C-43DC-9878-2BB78299FF31}',
    '{77F84D98-B590-41C9-954E-A922A789051F}',
    '{638F4F3A-870F-48BD-8CBF-2ED3D6CEE139}',
    '{278BE209-481F-44C0-BBCB-43AC665C9BED}',
    '{9C1E3A01-772F-4AA1-A36B-3C476B1D8069}',
    '{ECECE424-68BD-4057-8128-09FB41DF9AA3}'

    $OutboundProxyServersRules = 
    '{1CFA6C32-1C0C-44E9-8940-6578BC1DEBF6}',
    '{4D896BF4-2276-4DAB-A19D-12A438032CD3}',
    '{C356494C-8B03-49EA-86C9-6284959BEC0A}',
    '{F287CDD7-2E2D-4FC2-8153-FCE73D703F8C}',
    '{2BEED6C6-071D-4684-80A5-FCBA127AB3B8}',
    '{7B0A3582-A19F-41FE-8837-7F064EEBAC04}',
    '{1A884C71-20C9-4292-8F60-AC38222CA24D}',
    '{457BF377-745C-4B3B-9732-6523A84D96C5}',
    '{7855BBE0-8076-4D3C-A564-0BBF43D78310}'
        
    $OutboundDomainControllersRules = 
    '{1D5BB1AD-562A-4800-8D70-60BF0EF10531}',
    '{CF6963D8-8CCF-4580-B78A-8644F0F7D982}',
    '{45A03958-622B-4EBB-A27A-4EAE36EB2041}',
    '{1A1361E7-36E8-4022-8E88-4B51284FEF0E}',
    '{FBB4F6B7-F429-488E-B31C-0FD7AAFC657A}',
    '{DAEE009A-18CA-48FF-A4A6-C6C411577EDC}',
    '{ACA17873-D36F-4F9E-BFCC-F825E8244DFF}',
    '{F7C578F3-8346-450D-8322-9AB02E56B89C}',
    '{8800EFBD-8FBD-409E-9AEF-EF3B9A36D0CF}',
    '{7A3C4D61-E4D9-4425-AAC3-D2F26CDDC2D3}',
    '{F09FE220-2FE7-441E-B1DD-FBFD5AABF401}',
    '{AB948056-1926-4E38-815A-6F0DB9047F91}',
    '{D8DB381C-086F-4066-A134-8A4A9DF70AE0}',
    '{368DFBD9-C088-44E8-9E57-E1934B40033A}',
    '{FF1BD86E-7BE2-41AB-A51D-3E8F5858C29F}',
    '{78B9E45C-C680-4F2F-9C57-4A988D886F3D}',
    '{5062521C-789F-43A3-8EBC-E988387369E1}',
    '{7A6C16B1-8717-41FD-848F-3133EABD0457}',
    '{BAE8ABC9-817E-48FE-A778-D380F3F052AD}'
    
    $OutboundWebServersRules = 
    '{AAD5C065-7043-474E-8976-185068D26C73}',
    '{6C4AC4AB-596F-4911-9E1F-3C064BF5882A}'
    
    $InboundExternalVPNEndpointsRules = 
    '{516B8181-6B67-4978-BCFB-C9A449C292D1}',
    '{6D8DA039-A3B1-41D0-98C9-F5D0C0753790}'
    
    $OutboundExternalVPNEndpointsRules = 
    '{D8576910-5D61-4060-AF86-4D4000C3269F}'

    $OutboundDirectAccessServersRules = 
    '{CED6EDCB-ACEC-40BE-AEE1-C564B93C6364}'

    $OutboundCRLServersRules = 
    '{CF5B99A7-1457-4A9A-ABE5-DDE18858905F}',
    '{5E8C4752-59D1-4667-A049-7BAA5AC7C558}',
    '{445A0F5B-A6B5-45DE-AA51-916C94DE2EF7}'

    $OutboundWPAD_PACFileServersRules = 
    '{C571942E-894A-4225-B9AD-348D859EA660}',
    '{65CA3A6B-7E05-4140-937E-825CC8F46188}',
    '{5094D28B-2740-4AE8-8697-84BB211C02A6}'
   
    $TrustedDHCPSubnetsRules =
    '{CF6963D8-8CCF-4580-B78A-8644F0F7D982}',
    '{1D5BB1AD-562A-4800-8D70-60BF0EF10531}',
    '{1A1361E7-36E8-4022-8E88-4B51284FEF0E}',
    '{45A03958-622B-4EBB-A27A-4EAE36EB2041}',
    '{CF5B99A7-1457-4A9A-ABE5-DDE18858905F}',
    '{ACA17873-D36F-4F9E-BFCC-F825E8244DFF}',
    '{C356494C-8B03-49EA-86C9-6284959BEC0A}',
    '{F287CDD7-2E2D-4FC2-8153-FCE73D703F8C}',
    '{2BEED6C6-071D-4684-80A5-FCBA127AB3B8}',
    '{7B0A3582-A19F-41FE-8837-7F064EEBAC04}',
    '{8800EFBD-8FBD-409E-9AEF-EF3B9A36D0CF}',
    '{7A3C4D61-E4D9-4425-AAC3-D2F26CDDC2D3}',
    '{F09FE220-2FE7-441E-B1DD-FBFD5AABF401}',
    '{AB948056-1926-4E38-815A-6F0DB9047F91}',
    '{D8DB381C-086F-4066-A134-8A4A9DF70AE0}',
    '{1A884C71-20C9-4292-8F60-AC38222CA24D}',
    '{368DFBD9-C088-44E8-9E57-E1934B40033A}',
    '{C571942E-894A-4225-B9AD-348D859EA660}',
    '{78B9E45C-C680-4F2F-9C57-4A988D886F3D}',
    '{FF1BD86E-7BE2-41AB-A51D-3E8F5858C29F}',
    '{5062521C-789F-43A3-8EBC-E988387369E1}',
    '{5E8C4752-59D1-4667-A049-7BAA5AC7C558}',
    '{65CA3A6B-7E05-4140-937E-825CC8F46188}',
    '{457BF377-745C-4B3B-9732-6523A84D96C5}',
    '{7855BBE0-8076-4D3C-A564-0BBF43D78310}',
    '{BAE8ABC9-817E-48FE-A778-D380F3F052AD}',
    '{5094D28B-2740-4AE8-8697-84BB211C02A6}',
    '{445A0F5B-A6B5-45DE-AA51-916C94DE2EF7}',
    '{7A6C16B1-8717-41FD-848F-3133EABD0457}'

    $GPOSession = Open-NetGPO -PolicyStore "$DomainName\$TargetGPOName"
    foreach ($InboundTierXManagementServersRule in $InboundTierXManagementServersRules)
    {
        Set-NetFirewallRule -Name $InboundTierXManagementServersRule -GPOSession $GPOSession -RemoteAddress $TierXManagementServers
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
    foreach ($InboundExternalVPNEndpointsRule in $InboundExternalVPNEndpointsRules)
    {
        Set-NetFirewallRule -Name $InboundExternalVPNEndpointsRule -GPOSession $GPOSession -RemoteAddress $ExternalVPNEndpoints
    }
    foreach ($OutboundExternalVPNEndpointsRule in $OutboundExternalVPNEndpointsRules)
    {
        Set-NetFirewallRule -Name $OutboundExternalVPNEndpointsRule -GPOSession $GPOSession -RemoteAddress $ExternalVPNEndpoints
    }
    foreach ($OutboundDirectAccessServersRule in $OutboundDirectAccessServersRules)
    {
        Set-NetFirewallRule -Name $OutboundDirectAccessServersRule -GPOSession $GPOSession -RemoteAddress $DirectAccessServers
    }
    foreach ($OutboundCRLServersRule in $OutboundCRLServersRules)
    {
        Set-NetFirewallRule -Name $OutboundCRLServersRule -GPOSession $GPOSession -RemoteAddress $CRLServers
    }
    foreach ($OutboundWPAD_PACFileServersRule in $OutboundWPAD_PACFileServersRules)
    {
        Set-NetFirewallRule -Name $OutboundWPAD_PACFileServersRule -GPOSession $GPOSession -RemoteAddress $WPAD_PACFileServers
    }
    foreach ($TrustedDHCPSubnetsRule in $TrustedDHCPSubnetsRules)
    {
        Set-NetFirewallRule -Name $TrustedDHCPSubnetsRule -GPOSession $GPOSession -LocalAddress $TrustedDHCPSubnets
    }
    Save-NetGPO -GPOSession $GPOSession
}
else
{
   #Just putting these here for now and I'll add in some code to allow for these updates to be added to an existing policy
   #If you do want to manually update existing policies prior to the script update use the following lines so that the GUID remains consistent across versions
   $GPOSession = Open-NetGPO -PolicyStore "$DomainName\$TargetGPOName"
   New-NetFirewallRule -GPOSession $GPOSession -Name '{19e95b85-df9e-4f10-bf7c-afb3b95a5ad4}' -DisplayName 'SVCHOST IKEEXT (UDP-Out)' -Enabled True -Profile Any -Direction Outbound -Action Allow -RemoteAddress $ExternalVPNEndpoints -Protocol UDP -RemotePort '500','4500' -Program '%SystemRoot%\System32\svchost.exe' -Service 'IKEEXT' #Add to $OutboundExternalVPNEndpointsRules
   Get-NetFirewallRule -GPOSession $GPOSession -Name '{7A6C16B1-8717-41FD-848F-3133EABD0457}'|Get-NetFirewallPortFilter|Set-NetFirewallPortFilter -RemotePort '135','389','49152-65535' # Adding '49152-65535' to the remote ports in the WMIPRVSE (TCP-Out) rule
   Save-NetGPO -GPOSession $GPOSession
}
