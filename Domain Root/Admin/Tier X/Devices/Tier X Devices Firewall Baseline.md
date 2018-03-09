# Tier X Devices Firewall Baseline
The Tier X script will create a policy that has rules for client devices and rules defining which IP addresses are allowed to manage the 
tier device.  
## When Using tier x administration policies;  
 - The SSDP discovery service should be set to disabled when using  and the 'Turn off multicast name resolution'
group policy setting should be enabled.  
 - Remove all Appx packages that can be removed (Get-AppxPackage|Remove-AppxPackage).
 - Disable One Drive
 - Do not allow browsing to any websites other that those on the enterprise intranet.
