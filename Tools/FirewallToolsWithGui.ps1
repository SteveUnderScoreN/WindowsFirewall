<#
.DESCRIPTION
    A set of Windows Firewall tools to create PowerShell firewall commands or to import/export rules to/from group policy objects. It contains blocked connection scanning and
    navigation between Windows Forms via a back button (BackButton). 
.NOTES
    ExportExistingRulesToPowerShellCommands
        If a policy is created from the output of this script and that policy is linked to the same OU as the source policy the link order will determine which rule is applied.
        Because the GUID is copied from the source they are not unique across policies, under normal conditions both rules with the same display name would be applied but
        because they conflict the policy higher in the link order will have it's rule applied and that will overwrite the lower policy rule.
    Build 1808.10
#>

if ((Get-Host).Name -eq "ServerRemoteHost" -or $PSVersionTable.PSEdition -eq "Core")
{
    Write-Warning "This script invokes a GUI and cannot be run over a remot session or on PowerShell Core editions)"
    break
}

Add-Type -Assembly "System.Windows.Forms"
[System.Windows.Forms.Application]::EnableVisualStyles()

function GroupPoliciesWithExistingFirewallRules
{
    $GroupPolicyObjects = (Get-GPO -All).DisplayName
    foreach ($GroupPolicyObject in $GroupPolicyObjects)
    {
        $GroupPolicyObjectIndex ++
        if (Get-NetFirewallRule -PolicyStore "$DomainName\$GroupPolicyObject" -ErrorAction SilentlyContinue)
        {
            $ProgressBar.Value = ($GroupPolicyObjectIndex*(100/$GroupPolicyObjects.Count))
            $StatusBar.Text = "Scanning policy $GroupPolicyObject"
            [string[]]$Script:GroupPoliciesWithExistingFirewallRules += $GroupPolicyObject
        }
    }
    Remove-Variable -Name "GroupPolicyObjectIndex" -Force -ErrorAction SilentlyContinue
    $Script:GroupPoliciesWithExistingFirewallRules = $Script:GroupPoliciesWithExistingFirewallRules| Sort-Object
}

function GetComputerFileSystemVariables
{
    $DriveLetters = Invoke-Command -Session $ComputerPsSession -ScriptBlock {(Get-WmiObject "Win32_Volume").DriveLetter}
    $ProgramFiles = Invoke-Command -Session $ComputerPsSession -ScriptBlock {$env:ProgramFiles}
    $ProgramFilesX86 = Invoke-Command -Session $ComputerPsSession -ScriptBlock {${env:ProgramFiles(x86)}}
    $SystemRoot = Invoke-Command -Session $ComputerPsSession -ScriptBlock {$env:SystemRoot}
}

function PopUpMessage ($Message) # Need to use `r`n for newline
{
    $PopUpMessageForm = New-Object -TypeName Windows.Forms.Form -Property @{FormBorderStyle = "FixedDialog"; Location = @{X = ($ToolPageForm.Location.X + 25); Y = ($ToolPageForm.Location.Y + 25)};StartPosition = "Manual" ; MinimumSize = @{Width = 150; Height = 100}; MaximizeBox = $false; MinimizeBox = $false; ControlBox = $false; AutoScroll = $true}
    $PopUpMessageBottomButtonPanel = New-Object -TypeName Windows.Forms.Panel -Property @{Width = $PopUpMessageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $PopUpMessageAcceptButton = New-Object -TypeName Windows.Forms.Button -Property @{Text = "OK"; Anchor = "Right"}
    $PopUpMessageAcceptButton.Add_Click({$PopUpMessageForm.Close()})
    $PopUpMessageAcceptButton.Left = $PopUpMessageBottomButtonPanel.Width - $PopUpMessageAcceptButton.Width - 5
    $PopUpMessageForm.CancelButton = $PopUpMessageAcceptButton
    $PopUpMessageForm.AcceptButton = $PopUpMessageAcceptButton
    $PopUpMessageTextBox = New-Object -TypeName Windows.Forms.TextBox -Property @{Multiline = $true; BackColor = "GhostWhite"; ReadOnly = $true; Text = $Message; MinimumSize = @{Width = 141; Height = 70}; MaximumSize = @{Width = 500; Height = 500}}
    $PopUpMessageTextBox.Size = $PopUpMessageTextBox.PreferredSize
    $PopUpMessageForm.Width = $PopUpMessageTextBox.Width + 9
    $PopUpMessageForm.Height = $PopUpMessageTextBox.Height + 30
    $PopUpMessageBottomButtonPanel.Controls.Add($PopUpMessageAcceptButton)
    $PopUpMessageForm.Controls.Add($PopUpMessageBottomButtonPanel)
    $PopUpMessageForm.Controls.Add($PopUpMessageTextBox)
    [void]$PopUpMessageForm.ShowDialog()
}

function CancelAccept ($Message,$CancelButtonText,$AcceptButtonText) # Need to use `r`n for newline
{
    $CancelAcceptForm = New-Object -TypeName Windows.Forms.Form -Property @{FormBorderStyle = "FixedDialog"; Location = @{X = ($ToolPageForm.Location.X + 25); Y = ($ToolPageForm.Location.Y + 25)};StartPosition = "Manual" ; MinimumSize = @{Width = 200; Height = 100}; MaximizeBox = $false; MinimizeBox = $false; ControlBox = $false}
    $CancelAcceptForm.Add_Shown({$CancelAcceptAcceptButton.Focus()})
    $CancelAcceptBottomButtonPanel = New-Object -TypeName Windows.Forms.Panel -Property @{Width = $CancelAcceptForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $CancelAcceptCancelButton = New-Object -TypeName Windows.Forms.Button -Property @{Text = $CancelButtonText; Anchor = "Right"}
    $CancelAcceptCancelButton.Left = $CancelAcceptBottomButtonPanel.Width - $CancelAcceptCancelButton.Width - 5
    $CancelAcceptAcceptButton = New-Object -TypeName Windows.Forms.Button -Property @{Text = $AcceptButtonText; Anchor = "Right"}
    $CancelAcceptAcceptButton.Left = $CancelAcceptCancelButton.Left - $CancelAcceptAcceptButton.Width - 5
    $CancelAcceptAcceptButton.DialogResult = "OK"
    $CancelAcceptForm.CancelButton = $CancelAcceptCancelButton
    $CancelAcceptForm.AcceptButton = $CancelAcceptAcceptButton
    $CancelAcceptTextBox = New-Object -TypeName Windows.Forms.TextBox -Property @{Multiline = $true; BackColor = "GhostWhite"; ReadOnly = $true; Text = $Message; MinimumSize = @{Width = 191; Height = 70}}
    $CancelAcceptTextBox.Size = $CancelAcceptTextBox.PreferredSize
    $CancelAcceptForm.Width = $CancelAcceptTextBox.Width + 9
    $CancelAcceptForm.Height = $CancelAcceptTextBox.Height + 30
    $CancelAcceptBottomButtonPanel.Controls.Add($CancelAcceptCancelButton)
    $CancelAcceptBottomButtonPanel.Controls.Add($CancelAcceptAcceptButton)
    $CancelAcceptForm.Controls.Add($CancelAcceptBottomButtonPanel)
    $CancelAcceptForm.Controls.Add($CancelAcceptTextBox)
    return $CancelAcceptForm.ShowDialog() 
}

function UpdateDataSourceForComboBoxCell ($ArrayList,$DataGridView)
{
    $ComboBoxColumns = ($DataGridView.Columns.Where({$_.CellType.Name -eq "DataGridViewComboBoxCell"})).Name
    for ($Row = 0; $Row -lt $DataGridView.Rowcount; $Row++)
    {
        foreach ($ComboBoxColumn in $ComboBoxColumns)
        {
            $DataGridView.rows[$Row].Cells[$ComboBoxColumn].DataSource = $ArrayList[$Row].$ComboBoxColumn
            $DataGridView.rows[$Row].Cells[$ComboBoxColumn].Value = $ArrayList[$Row].$ComboBoxColumn[0]
        } 
    }
}

function DomainResources
{
    # Version 0.7.0 domain resources
    $DomainControllers = "127.0.0.1","SERVERNAME"
    $ProxyServerPorts = "8080"
    $ProxyServers = "LocalSubnet","Intranet"
    $DnsServers = $DomainControllers # Specify these if you do not have DNS on each domain controller or you have additional DNS servers
    $CrlServers = "LocalSubnet","Intranet"
    $Wpad_PacFileServers = "LocalSubnet","Intranet"
    $TierXManagementServers = "LocalSubnet","Intranet" # These are used in tier X firewall baselines to define which computers can manage the device at a particular tier
    $SqlServers = "127.0.0.4"
    $WebServers = "LocalSubnet","Intranet"
    $FileServers = "LocalSubnet","Intranet"
    $KeyManagementServers = "LocalSubnet","Intranet"
    $BackupServers = "127.0.0.1"
    $ClusteredNodesAndManagementAddresses = "LocalSubnet","Intranet"
    $ExternalVpnEndpoints = "127.0.0.2 -  127.0.0.3" # This is the externally resolvable IPSec hostname or address
    $DirectAccessServers = "127.0.0.128/25" # This is the externally resolvable hostname or address of the DirectAccess IPHTTPS endpoint
    $TrustedDhcpSubnets = "Any" # This is client enterprise subnets and includes subnets issued by the VPN server, "Predefined set of computers" cannot be used here
    # END of version 0.7.0 domain resources
    # Version 0.8.0 domain resources
    $ServerRoleAdministrationServers = "LocalSubnet","Intranet" # These are trusted machines used by tier administrators permitted to administer a server role
    # END of version 0.8.0 domain resources
    $Resources = "DomainControllers","ProxyServers","DnsServers","CrlServers","Wpad_PacFileServers","TierXManagementServers","SqlServers","WebServers","FileServers","KeyManagementServers","BackupServers","ClusteredNodesAndManagementAddresses","ExternalVpnEndpoints","DirectAccessServers","TrustedDhcpSubnets","ServerRoleAdministrationServers"
    foreach ($Resource in $Resources)
    {
        $ResourceIndex ++
        Write-Progress -Activity "Updating resource arrays" -Status "$Resource" -PercentComplete ($ResourceIndex*(100/$Resources.Count))
        $Addresses = @()
        $Names = (Get-Variable -Name $Resource).Value
        foreach ($Name in $Names.replace(" ",""))
        {
            switch -Wildcard ($Name)
            {
                "*/*"           {
                                    $Addresses += $Name # A forward slash indicates a subnet has been specified
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
                                            $Addresses += $Name # If each side of the hyphen is an IP address then a range has been specified
                                        }
                                    }
                                    catch [Management.Automation.PSInvalidCastException]
                                    {
                                        . AttemptResolveDnsName $Name
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
                                        . AttemptResolveDnsName $Name
                                    }
                                }
            }
        }
        Set-Variable -Name $Resource -Value $Addresses
    }
    Write-Progress -Activity "Updating resource arrays" -Completed
    Remove-Variable ResourceIndex
}

function AttemptResolveDnsName ($Name)
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

function FindAllPoliciesWithFirewallRulesPage
{
    $ToolPageForm = New-Object -TypeName Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; Location = $ToolSelectionPageForm.Location; StartPosition = "Manual"; Size = $ToolSelectionPageForm.Size; MinimumSize = $ToolSelectionPageForm.MinimumSize; WindowState = $ToolSelectionPageForm.WindowState; Text = "Find all policies with firewall rules"} 
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar -Property @{Anchor = "Left"}
            $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($ProgressBar)
            $FindAllPoliciesWithFirewallRulesGpoListBox.Hide()
            $StatusBar = $FindAllPoliciesWithFirewallRulesStatusBar
            . GroupPoliciesWithExistingFirewallRules
            $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Remove($ProgressBar)
        }
        foreach ($FindAllPoliciesWithFirewallRules in $Script:GroupPoliciesWithExistingFirewallRules)
        { # Loop through GPOs and add to listbox 
            [void]$FindAllPoliciesWithFirewallRulesGpoListBox.Items.Add($FindAllPoliciesWithFirewallRules)
        }
        $FindAllPoliciesWithFirewallRulesStatusBar.Text = "$($FindAllPoliciesWithFirewallRulesGpoListBox.Items.Count) group policies with firewall rules were found."
        $DefaultPageCancelButton.Left = $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $FindAllPoliciesWithFirewallRulesSaveAsButton.Left = $DefaultPageCancelButton.Left - $FindAllPoliciesWithFirewallRulesSaveAsButton.Width - 5 
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesSaveAsButton)
        $FindAllPoliciesWithFirewallRulesGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged({$ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState})
    $FindAllPoliciesWithFirewallRulesBottomButtonPanel = New-Object -TypeName Windows.Forms.Panel -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $FindAllPoliciesWithFirewallRulesSaveFileDialog =  New-Object -TypeName System.Windows.Forms.SaveFileDialog
    $FindAllPoliciesWithFirewallRulesSaveFileDialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
    $FindAllPoliciesWithFirewallRulesSaveAsButton = New-Object -TypeName Windows.Forms.Button -Property @{Text = "Save As"; Anchor = "Right"} 
    $FindAllPoliciesWithFirewallRulesSaveAsButton.Add_Click(
    {
        if ($FindAllPoliciesWithFirewallRulesSaveFileDialog.ShowDialog() -eq "OK")
        {
            $FindAllPoliciesWithFirewallRulesGpoListBox.Items| Out-File -FilePath $FindAllPoliciesWithFirewallRulesSaveFileDialog.FileName
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $FindAllPoliciesWithFirewallRulesGpoListBox = New-Object -TypeName System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $FindAllPoliciesWithFirewallRulesStatusBar = New-Object -TypeName Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Scanning policies."} 
    $FindAllPoliciesWithFirewallRulesPanel = New-Object -TypeName Windows.Forms.Panel -Property @{AutoScroll = $true; Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
    $FindAllPoliciesWithFirewallRulesPanel.Controls.Add($FindAllPoliciesWithFirewallRulesGpoListBox)
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesBottomButtonPanel)
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function UpdateDomainResourcesPage
{
    . PopUpMessage -Message "Tool not available in this build."
}

function EditExistingFirewallRulesPage
{   
    class WindowsFirewallRule
    {
        [string] $PolicyStore
        [string] $Name
        [string] $DisplayName
        [string] $Description
        [string] $Group 
        [ValidateSet("True", "False")]
        [String] $Enabled
        [ValidateSet("Any", "Domain","Private","Public")]
        [collections.arraylist] $Profile
        [ValidateSet("Inbound", "Outbound")]
        [string] $Direction
        [ValidateSet("Allow", "Deny")]
        [string] $Action
        [collections.arraylist] $LocalAddress
        [collections.arraylist] $RemoteAddress
        [string] $Protocol
        [collections.arraylist] $LocalPort
        [collections.arraylist] $RemotePort
        [string] $Program
        [string] $Package
        [string] $Service
    }
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{FormBorderStyle = "Sizable"; Location = $ToolSelectionPageForm.Location; StartPosition = "Manual"; Size = $ToolSelectionPageForm.Size; MinimumSize = $ToolSelectionPageForm.MinimumSize; WindowState = $ToolSelectionPageForm.WindowState; Text = "Edit existing firewall rules"} 
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{Anchor = "Left"}
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($ProgressBar)
            $EditExistingFirewallRulesGpoListBox.Hide()
            $StatusBar = $EditExistingFirewallRulesStatusBar
            . GroupPoliciesWithExistingFirewallRules
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Remove($ProgressBar)
        }
        foreach ($EditExistingFirewallRules in $Script:GroupPoliciesWithExistingFirewallRules)
        { 
            [void]$EditExistingFirewallRulesGpoListBox.Items.Add($EditExistingFirewallRules) # Loop through GPOs and add to listbox 
        }
        $EditExistingFirewallRulesStatusBar.Text = "Please select a GPO to display."
        $DefaultPageCancelButton.Left = $EditExistingFirewallRulesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $EditExistingFirewallRulesAcceptButton.Left = $DefaultPageCancelButton.Left - $EditExistingFirewallRulesAcceptButton.Width - 5
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesAcceptButton)
        $EditExistingFirewallRulesGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged({$ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState})
    $ToolPageForm.Add_FormClosing({
        if ((. CancelAccept -Message "Are you sure, changes will be lost? (check button focus)" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "Cancel")
        {
            Write-Host "Cancel selected"
            {$_.Cancel = $true}
        }
    })
    $EditExistingFirewallRulesBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $EditExistingFirewallRulesAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{Text = "Select"; Anchor = "Right"} 
    $EditExistingFirewallRulesAcceptButton.Add_Click(
    {
        if ($EditExistingFirewallRulesGpoListBox.Parent)
        {
            $EditExistingFirewallRulesRulesListBox.Items.Clear()
            $GpoSession = Open-NetGPO -PolicyStore "$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)"
            $Script:EditExistingFirewallRulesRulesArray = @()
            foreach ($EditExistingFirewallRulesRule in (Get-NetFirewallRule -GPOSession $GpoSession))
            {
                $Script:EditExistingFirewallRulesRulesArray += "$($EditExistingFirewallRulesRule.Name)"
                $EditExistingFirewallRulesRulesListBox.Items.Add($EditExistingFirewallRulesRule.DisplayName)
            }
            $EditExistingFirewallRulesRulesListBox.SelectionMode = "MultiExtended"
            $EditExistingFirewallRulesStatusBar.Text = "Please select one or more rules to display."
            $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesBackButton)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesGpoListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
            $EditExistingFirewallRulesRulesListBox.Focus()
            Remove-Variable -Name "GpoSession" -Force -ErrorAction SilentlyContinue
        }
        elseif ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            $GpoSession = Open-NetGPO -PolicyStore ("$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)")
            $Script:WindowsFirewallRules = New-Object -TypeName "System.Collections.ArrayList"
            foreach ($EditExistingFirewallRulesRule in (Get-NetFirewallRule -GPOSession $GpoSession -Name $EditExistingFirewallRulesRulesArray[$EditExistingFirewallRulesRulesListBox.SelectedIndices]))
            {
                $EditExistingFirewallRulesStatusBar.Text = "Importing rule $($EditExistingFirewallRulesRule.Name)."
                $WindowsFirewallRule = New-Object -TypeName "WindowsFirewallRule" -Property @{
                    PolicyStore = ("$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)")
                    Name = $EditExistingFirewallRulesRule.Name
                    DisplayName = $EditExistingFirewallRulesRule.DisplayName
                    Description = $EditExistingFirewallRulesRule.Description
                    Group = $EditExistingFirewallRulesRule.Group
                    Enabled = $EditExistingFirewallRulesRule.Enabled
                    Profile = @($EditExistingFirewallRulesRule.Profile)
                    Direction = $EditExistingFirewallRulesRule.Direction
                    Action = $EditExistingFirewallRulesRule.Action
                    LocalAddress = @(($EditExistingFirewallRulesRule| Get-NetFirewallAddressFilter -GPOSession $GpoSession).LocalAddress)
                    RemoteAddress = @(($EditExistingFirewallRulesRule| Get-NetFirewallAddressFilter -GPOSession $GpoSession).RemoteAddress)
                    Protocol = ($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).Protocol
                    LocalPort = @(($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).LocalPort)
                    RemotePort = @(($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).RemotePort)
                    Program = ($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Program
                    Package = ($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package
                    Service = ($EditExistingFirewallRulesRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service
                }
                [System.Collections.ArrayList]$Script:WindowsFirewallRules += $WindowsFirewallRule
            }
            $EditExistingFirewallRulesDataGridView.DataSource = $Script:WindowsFirewallRules
            $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
            $EditExistingFirewallRulesStatusBar.Text = "$($Script:WindowsFirewallRules.Count) rules imported."
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesDataGridView)
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesBackButton)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRulesListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesDataGridView)
            $EditExistingFirewallRulesDataGridView.Focus()
            . UpdateDataSourceForComboBoxCell -ArrayList $Script:WindowsFirewallRules -DataGridView $EditExistingFirewallRulesDataGridView
            Remove-Variable -Name "GpoSession" -Force -ErrorAction SilentlyContinue
        }
        elseif ($EditExistingFirewallRulesDataGridView.Parent)
        {
            . PopUpMessage -Message "Save changes to file or to GPO goes here."
        }
    })
    $EditExistingFirewallRulesBackButton = New-Object -TypeName "Windows.Forms.Button" -Property @{Text = "Back"; Anchor = "Right"}
    $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
    $EditExistingFirewallRulesBackButton.Add_Click(
    {
        if ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Remove($EditExistingFirewallRulesBackButton)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRulesListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
        }
        elseif ($EditExistingFirewallRulesDataGridView.Parent)
        {
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesDataGridView)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ToolPageForm.AcceptButton = $EditExistingFirewallRulesAcceptButton
    $EditExistingFirewallRulesGpoListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesGpoListBox.Add_DoubleClick(
    {
       $EditExistingFirewallRulesAcceptButton.PerformClick()
    })
    $EditExistingFirewallRulesRulesListBox = New-Object "System.Windows.Forms.ListBox" -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesRulesListBox.Add_DoubleClick(
    {
        $EditExistingFirewallRulesAcceptButton.PerformClick()
    })
    $EditExistingFirewallRulesDataGridView = New-Object -TypeName "System.Windows.Forms.DataGridView" -Property @{AutoSize = $true; BackGroundColor = "WhiteSmoke"; Dock = "Fill"; AutoGenerateColumns = $false; ColumnHeadersHeightSizeMode = 'AutoSize'}
    $EditExistingFirewallRulesDataGridView.Columns.Insert(0, (New-Object -TypeName "System.Windows.Forms.DataGridViewCheckBoxColumn"))
    $EditExistingFirewallRulesDataGridView.Columns[0].AutoSizeMode = "AllCellsExceptHeader"
    $ColumnIndex = 1
    $EmptyWindowsFirewallRule = New-Object -TypeName "WindowsFirewallRule"
    foreach ($PropertyName in ($EmptyWindowsFirewallRule.PsObject.Properties).name)
    {
        if ($PropertyName -ne "PolicyStore" -and $PropertyName -ne "Name")
        {
            if ($PropertyName -in "DisplayName","Description","Group","Enabled","Direction","Action","Protocol","Program","Package","Service")
            {
                $EditExistingFirewallRulesDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewTextBoxColumn" -Property @{ReadOnly = $true}))
                $EditExistingFirewallRulesDataGridView.Columns[$ColumnIndex].Name = $PropertyName
                $EditExistingFirewallRulesDataGridView.Columns["$PropertyName"].DataPropertyName = $PropertyName
                $ColumnIndex ++
            }
            else
            {
                $EditExistingFirewallRulesDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewComboBoxColumn" -Property @{ReadOnly = $false}))
                $EditExistingFirewallRulesDataGridView.Columns[$ColumnIndex].Name = $PropertyName
                $ColumnIndex ++
            }
        }
    }
    $EditExistingFirewallRulesStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{Dock = "Bottom"; Text = "Please select a GPO to display."} 
    $EditExistingFirewallRulesPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
    $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesBottomButtonPanel)
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function ScanComputerForBlockedConnectionsPage
{
    class NetworkConnection
    {
        [int] $ProcessId
        [string] $Application
        [string] $Direction
        [ipaddress] $SourceAddress
        [int] $SourcePort
        [ipaddress] $DestAddress
        [int] $DestPort
        [string] $Protocol
        [collections.arraylist] $Service
        [string] $Notes
    }
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{FormBorderStyle = "FixedDialog"; Location = @{X = ($ToolSelectionPageForm.Location.X + ($ToolSelectionPageForm.width/2)) - 125; Y = ($ToolSelectionPageForm.Location.Y + ($ToolSelectionPageForm.Height/2)) - 55}; StartPosition = "Manual"; Width = 250; Height = 110; Text = "Scan computer for blocked connections"; MaximizeBox = $false; MinimizeBox = $false; ControlBox = $false}
    $ScanComputerForBlockedConnectionsBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ScanComputerForBlockedConnectionsCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{Text = "Exit"; Anchor = "Right"}
    $ScanComputerForBlockedConnectionsCancelButton.Left = $ScanComputerForBlockedConnectionsBottomButtonPanel.Width - $ScanComputerForBlockedConnectionsCancelButton.Width - 5
    $ScanComputerForBlockedConnectionsCancelButton.Add_Click({$ToolSelectionPageForm.Show()}) 
    $ScanComputerForBlockedConnectionsAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{Text = "Scan"; Anchor = "Right"} 
    $ScanComputerForBlockedConnectionsAcceptButton.Left = $ScanComputerForBlockedConnectionsCancelButton.Left - $ScanComputerForBlockedConnectionsAcceptButton.Width - 5
    $ScanComputerForBlockedConnectionsAcceptButton.Add_Click(
    {
        if ($ScanComputerForBlockedConnectionsTextBox.Parent)
        {
            [String]$Computer = $ScanComputerForBlockedConnectionsTextBox.Text
            try
            {
                try
                {
                    if ([ipaddress]$Computer)
                    {
                        [ipaddress]$IpAddresses = $Computer
                    }
                }
                catch [Management.Automation.PSInvalidCastException]
                {
                    $ScanComputerForBlockedConnectionsStatusBar.Text =  "Resolving IP addresses."
                    [ipaddress[]]$IpAddresses = (Resolve-DnsName $Computer -ErrorAction Stop).IpAddress
                }
                #Remove-Variable -Name "JobNumber" -Force -ErrorAction SilentlyContinue
                #Remove-Variable -Name "NetworkConnectivityJobs" -Force -ErrorAction SilentlyContinue
                foreach ($IpAddress in $IpAddresses) # Because Test-NetConnection does the IP addresses one after another, uses Ping and doesn't provide feedback during the test I've opted to use asynchronous TCP jobs and monitor for the state of those. This also allows me to abandon the jobs if the tests are taking too long.
                {
                    $JobNumber += 1
                    if ($IpAddress.AddressFamily -eq "InterNetworkV6")
                    {
                        $TcpClient = New-Object -TypeName "System.Net.Sockets.TcpClient"("InterNetworkV6")
                    }
                    else
                    {
                        $TcpClient = New-Object -TypeName "System.Net.Sockets.TcpClient"("InterNetwork")
                    }
                    New-Variable -Name ("NetworkConnectivityJobs" + "$JobNumber") -Value ($TcpClient.ConnectAsync($IpAddress,135))
                    [array]$NetworkConnectivityJobs += Get-Variable -Name ("NetworkConnectivityJobs" + "$JobNumber")
                }
                $WaitTime = (Get-Date).AddSeconds(10)
                #Remove-Variable -Name "NetworkConnectivityJobRanToCompletion" -Force -ErrorAction SilentlyContinue
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Trying $(($NetworkConnectivityJobs).Count) IP address/es."
                do
                {
                    $NetworkConnectivityJobRanToCompletion = $false
                    $JobsWaitingForActivation = $false
                    foreach ($NetworkConnectivityJob in $NetworkConnectivityJobs)
                    {
                        if ($NetworkConnectivityJob.Value.Status -eq "RanToCompletion")
                        {
                            $NetworkConnectivityJobRanToCompletion = $true
                        }
                        if ($NetworkConnectivityJob.Value.Status -eq "WaitingForActivation")
                        {
                            $JobsWaitingForActivation = $true
                        }
                    }
                    if ($NetworkConnectivityJobRanToCompletion -eq $false)
                    {
                        if ($JobsWaitingForActivation -eq $false)
                            {
                            if ((. CancelAccept -Message "All network connectivity jobs have failed,`r`ndo you want to display diagnostic information?" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "OK")
                            {
                                #Remove-Variable -Name "DiagnosticResults" -Force -ErrorAction SilentlyContinue
                                foreach ($NetworkConnectivityJob in $NetworkConnectivityJobs)
                                {
                                    [array]$DiagnosticResults += $NetworkConnectivityJob.Value.Exception.InnerException
                                }
                                . PopUpMessage -Message $DiagnosticResults
                                throw "Connectivity test failed."   
                            }
                        }
                        if ((Get-Date) -gt $WaitTime)
                        {
                            if ((. CancelAccept -Message "Network connectivity tests are taking longer than expected,`r`nthis function requires TCP ports 135,5985 and 49152-65535.`r`nDo you want to continue?" -CancelButtonText "Abort" -AcceptButtonText "Continue") -eq "Cancel")
                            {
                                throw "Connectivity test aborted, scanning cancelled."
                            }
                            $WaitTime = (Get-Date).AddSeconds(10)
                        }
                        Start-Sleep -Milliseconds 500
                    }
                }
                Until ($NetworkConnectivityJobRanToCompletion -eq $true)
                [datetime]$NetworkStateChange =  (Get-WinEvent -ComputerName $Computer -FilterHashtable @{LogName = "Microsoft-Windows-NetworkProfile/Operational"; ID = 4004} -MaxEvents 1 -ErrorAction Stop).TimeCreated.AddSeconds("1")
                if ((Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"}))
                {
                    if ((. CancelAccept -Message "A $((Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"}).State) job has been found for this computer.`r`nDo you wants to connect to that job or start a new scan?" -CancelButtonText "New" -AcceptButtonText "Connect") -eq "Cancel")
                    {
                        (Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"})| Remove-Job
                        $EventsJob = Invoke-Command -ComputerName $Computer -ScriptBlock {$Events = (Get-WinEvent -FilterHashtable @{LogName = "Security"; ID = 5157; StartTime = $args[0]} -ErrorAction Stop); $Events} -AsJob -ArgumentList $NetworkStateChange
                    }
                    else
                    {
                        $EventsJob = (Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"})
                    }
                }
                else
                {
                    $EventsJob = Invoke-Command -ComputerName $Computer -ScriptBlock {$Events = (Get-WinEvent -FilterHashtable @{LogName = "Security"; ID = 5157; StartTime = $args[0]} -ErrorAction Stop); $Events} -AsJob -ArgumentList $NetworkStateChange
                }
                $WaitTime = (Get-Date).AddSeconds(60)
                do
                {
                    $IndexNumber ++
                    $CharacterArray = ("--  ").ToCharArray()
                    $ScanComputerForBlockedConnectionsStatusBar.Text = "Scanning $Computer, please wait. $([string]($CharacterArray[-$IndexNumber..($CharacterArray.Count - $IndexNumber)]))"
                    if ($IndexNumber -eq $CharacterArray.Count)
                    {
                        $IndexNumber = 0
                    }
                    if ((Get-Date) -gt $WaitTime)
                    {
                        if ((. CancelAccept -Message "$Computer`r`nscanning is taking longer than expected. If you`r`nabort waiting for this scan to complete the scan`r`nwill continue in the background and you can`r`ntry to get the results by starting a scan on`r`n$Computer`r`nDo you want to continue?" -CancelButtonText "Abort" -AcceptButtonText "Continue") -eq "Cancel")
                        {
                            throw "Waiting for scan job to complete aborted."
                        }
                        $WaitTime = (Get-Date).AddSeconds(60)
                    }
                    start-sleep -Milliseconds 500
                }
                while ($EventsJob.State -eq "Running")
                $Events = $EventsJob| Receive-Job -Keep -ErrorAction SilentlyContinue
                if ($EventsJob.State -eq "Failed")
                {
                    if ($error[0].Exception.Message -eq "No events were found that match the specified selection criteria.")
                    {
                        throw "No events were found that match the specified selection criteria."
                    }
                    else
                    {
                        throw
                    }
                }
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Collecting additional details."
                $ComputerCimSession = New-CimSession -ComputerName $Computer
                #$RunningSvchostServices = Get-CimInstance -CimSession $ComputerCimSession -Class "Win32_Service" -Filter "PathName LIKE '%svchost.exe%' AND State = 'Running'"
                $RunningServices = Get-CimInstance -CimSession $ComputerCimSession -Class "Win32_Service" -Filter "State = 'Running'"
                $ComputerCimSession| Remove-CimSession
                $ComputerPsSession = New-PSSession -ComputerName $Computer
                . GetComputerFileSystemVariables 
                [array]$AdHarvest = Invoke-Command -Session $ComputerPsSession -ScriptBlock {(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ADHarvest\" -Name "LastFetchContents").LastFetchContents.Split(",")}
                #$AdHarvest.Count
                $ComputerPsSession| Remove-PSSession
                [NetworkConnection[]]$InboundNetworkConnections = @()
                [NetworkConnection[]]$OutboundNetworkConnections = @()
                $EventCount = 1
                $EventTotal = ($Events.Message).Count
                foreach ($Event in $Events.Message)
                {
                    #if (($Event.Event.EventData.Data.Where({$_.Name -EQ "Application"})).'#text' -like "\device\harddiskvolume*")
                    #    {
                    #        $HardDiskVolume = ((Select-String -InputObject (($Event.Event.EventData.Data.Where({$_.Name -EQ "Application"})).'#text') -Pattern '\\device\\harddiskvolume') -split("\\"))[2].TrimStart("harddiskvolume")
                    #        $Drive = (Get-Variable -Name HardDiskVolume$HardDiskVolume).Value
                    #    }
                    $ScanComputerForBlockedConnectionsStatusBar.Text = "Sorting $EventCount of $EventTotal."
                    $EventCount ++
                    $NetworkConnection = New-Object -TypeName "NetworkConnection"
                    $EventMessage = $Event.Split("`n").TrimStart().TrimEnd()
                    $NetworkConnection.ProcessID = $EventMessage[3].TrimStart("Process ID:").TrimStart()
                    $NetworkConnection.Application = $EventMessage[4].TrimStart("Application Name:").TrimStart() -replace "\\device\\harddiskvolume\d+\\windows\\","%SystemRoot%\"  # -replace "\\device\\harddiskvolume\d+","$Drive" - Will need to search remote drives to populate the HarddiskVolume variables.
                    $NetworkConnection.Direction = $EventMessage[7].TrimStart("Direction:").TrimStart()
                    $NetworkConnection.SourceAddress = $EventMessage[8].TrimStart("Source Address:").TrimStart()
                    $NetworkConnection.SourcePort = $EventMessage[9].TrimStart("Source Port:").TrimStart()
                    $NetworkConnection.DestAddress = $EventMessage[10].TrimStart("Destination Address:").TrimStart()
                    $NetworkConnection.DestPort = $EventMessage[11].TrimStart("Destination Port:").TrimStart()
                    $NetworkConnection.Protocol = $EventMessage[12].TrimStart("Protocol:").TrimStart() -replace "^1$","ICMPv4" -replace "^6$","TCP" -replace "^17$","UDP" -replace "^58$","ICMPv6"
                    $NetworkConnection.Service = @(($RunningServices.Where({$_.ProcessId -eq $NetworkConnection.ProcessID})).Name)
                    if ($NetworkConnection.Service)
                    {
                        $NetworkConnection.Notes += "Service:$(($RunningServices.Where({$_.ProcessId -eq $NetworkConnection.ProcessID})).DisplayName)"
                    }
                    if ($NetworkConnection.Direction -eq "Inbound")
                    {
                        $InboundNetworkConnections += $NetworkConnection
                    }
                    else
                    {
                        $OutboundNetworkConnections += $NetworkConnection
                    }
                }
                [NetworkConnection[]]$FilteredOutboundNetworkConnections = $OutboundNetworkConnections| Select-Object -Property * -ExcludeProperty "SourcePort" -Unique
                [NetworkConnection[]]$FilteredInboundNetworkConnections = $InboundNetworkConnections| Select-Object -Property * -ExcludeProperty "DestPort" -Unique
                [System.Collections.ArrayList]$NetworkConnections += $FilteredOutboundNetworkConnections
                [System.Collections.ArrayList]$NetworkConnections += $FilteredInboundNetworkConnections
                $ScanComputerForBlockedConnectionsDataGridView.DataSource = $NetworkConnections
                $ScanComputerForBlockedConnectionsDataGridView.Columns["ProcessId"].Visible = $false
                $ScanComputerForBlockedConnectionsDataGridView.Columns["SourcePort"].Visible = $false
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Please select one or more rules to create."
                $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsTextBox)
                $ToolPageForm.FormBorderStyle = "Sizable"
                $ToolPageForm.Location = $ToolSelectionPageForm.Location
                $ToolPageForm.Size = $ToolSelectionPageForm.Size
                $ToolPageForm.MinimumSize = $ToolSelectionPageForm.MinimumSize
                $ToolPageForm.WindowState = $ToolSelectionPageForm.WindowState
                $ToolPageForm.MaximizeBox = $true
                $ToolPageForm.MinimizeBox = $true
                $ToolPageForm.ControlBox = $true
                $ScanComputerForBlockedConnectionsAcceptButton.Text = "Create"
                $ScanComputerForBlockedConnectionsBackButton.Left = $ScanComputerForBlockedConnectionsAcceptButton.Left - $ScanComputerForBlockedConnectionsBackButton.Width - 5
                $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsBackButton)
                $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsDataGridView)
                $ScanComputerForBlockedConnectionsDataGridView.Focus()
                . UpdateDataSourceForComboBoxCell -ArrayList $NetworkConnections -DataGridView $ScanComputerForBlockedConnectionsDataGridView
            }
            catch [System.Management.Automation.RuntimeException]
            {
                if ($error[0].Exception.Message -eq "Connectivity test aborted, scanning cancelled.")
                {
                }
                if ($error[0].Exception.Message -eq "Waiting for scan job to complete aborted.")
                {
                }
                elseif ($error[0].Exception.Message -eq "Connectivity test failed.")
                {
                    . PopUpMessage -Message "Connectivity test failed, is`r`n$Computer`r`navalable on the network and are`r`nTCP ports 135,5985 and 49152-65535`r`nopen from this computer."
                }
                elseif ($error[0].Exception.Message -like "*: DNS name does not exist")
                {
                    . PopUpMessage -Message "The hostname $Computer couldn not be resolved,`r`ncheck connectivity to the DNS infrastructure`r`nand check there is a valid host record for`r`n$Computer."
                }
                elseif ($error[0].Exception.Message -eq "No events were found that match the specified selection criteria.")
                {
                    . PopUpMessage -Message "No matching events were found since the last network`r`nstate change on $(($NetworkStateChange.AddSeconds(-1)).ToString()), event ID 4004 in`r`nlog 'Microsoft-Windows-NetworkProfile/Operational'"
                }
                else
                {
                    . PopUpMessage -Message "Scan failed.`r`n$($error[0].Exception.Message)System.Management.Automation.RuntimeException"
                }
            }
            catch
            {
                . PopUpMessage -Message "Scan failed.`r`n$($error[0].Exception.Message)"
            }
        }
        elseif ($ScanComputerForBlockedConnectionsDataGridView.Parent)
        {
             . PopUpMessage -Message "Tool not available in this build."
        #    $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsDataGridView)
        #    $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsBuildRules)
        }
        #elseif ($ScanComputerForBlockedConnectionsBuildRules.Parent)
        #{
        #    . PopUpMessage -Message "Tool not available in this build."
        #}
        if ($ScanComputerForBlockedConnectionsTextBox.Parent)
        {
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
        }
    })
    $ScanComputerForBlockedConnectionsBackButton = New-Object -TypeName "Windows.Forms.Button" -Property @{Text = "Back"; Anchor = "Right"}
    $ScanComputerForBlockedConnectionsBackButton.Left = $ScanComputerForBlockedConnectionsAcceptButton.Left - $ScanComputerForBlockedConnectionsBackButton.Width - 5
    $ScanComputerForBlockedConnectionsBackButton.Add_Click(
    {
        if ($ScanComputerForBlockedConnectionsDataGridView.Parent)
        {
            $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Remove($ScanComputerForBlockedConnectionsBackButton)
            $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsDataGridView)
            $ToolPageForm.FormBorderStyle = "FixedDialog"
            $ToolPageForm.Location = @{X = ($ToolSelectionPageForm.Location.X + ($ToolSelectionPageForm.width/2)) - 125; Y = ($ToolSelectionPageForm.Location.Y + ($ToolSelectionPageForm.Height/2)) - 55}
            $ToolPageForm.MinimumSize = @{Width = 0; Height = 0}
            $ToolPageForm.Size = @{Width = 250; Height = 110}
            $ToolPageForm.WindowState = "Normal"
            $ToolPageForm.MaximizeBox = $false
            $ToolPageForm.MinimizeBox = $false
            $ToolPageForm.ControlBox = $false
            $ScanComputerForBlockedConnectionsAcceptButton.Text = "Scan"
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
            $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsTextBox)
        }
        #elseif ($ScanComputerForBlockedConnectionsBuildRules.Parent)
        #{
        #    $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsBuildRules)
        #    $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsDataGridView)
        #}
    })
    $ToolPageForm.CancelButton = $ScanComputerForBlockedConnectionsCancelButton
    $ToolPageForm.AcceptButton = $ScanComputerForBlockedConnectionsAcceptButton
    $ScanComputerForBlockedConnectionsDataGridView = New-Object -TypeName "System.Windows.Forms.DataGridView" -Property @{AutoSize = $true; BackGroundColor = "WhiteSmoke"; Dock = "Fill"; AutoGenerateColumns = $false; ColumnHeadersHeightSizeMode = 'AutoSize'}
    $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert(0, (New-Object -TypeName "System.Windows.Forms.DataGridViewCheckBoxColumn"))
    $ScanComputerForBlockedConnectionsDataGridView.Columns[0].AutoSizeMode = "AllCellsExceptHeader"
    $ColumnIndex = 1
    $EmptyNetworkConnection = New-Object -TypeName "NetworkConnection"
    foreach ($PropertyName in ($EmptyNetworkConnection.PsObject.Properties).name)
    {
            if ($PropertyName -in "ProcessId","Application","Direction","SourceAddress","SourcePort","DestAddress","DestPort","Protocol","Notes")
            {
                $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewTextBoxColumn" -Property @{ReadOnly = $true}))
                $ScanComputerForBlockedConnectionsDataGridView.Columns[$ColumnIndex].Name = $PropertyName
                $ScanComputerForBlockedConnectionsDataGridView.Columns["$PropertyName"].DataPropertyName = $PropertyName
                $ColumnIndex ++
            }
            else
            {
                $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewComboBoxColumn" -Property @{ReadOnly = $true}))
                $ScanComputerForBlockedConnectionsDataGridView.Columns[$ColumnIndex].Name = $PropertyName
                $ColumnIndex ++
            }
    }
    $ScanComputerForBlockedConnectionsTextBox = New-Object -TypeName Windows.Forms.TextBox -Property @{width = $ToolPageForm.Width - 36; Location = @{X = 10; Y= 5}; Text = "LocalHost"}
    $ScanComputerForBlockedConnectionsStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{Dock = "Bottom"; Text = "Enter a computer name or IP address to scan."}
    $ScanComputerForBlockedConnectionsPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
    $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsTextBox)
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsCancelButton)
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsAcceptButton)
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsBottomButtonPanel)
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsStatusBar)
    [void]$ToolPageForm.ShowDialog()
}

function ExportExistingRulesToPowerShellCommandsPage
{
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{FormBorderStyle = "Sizable"; Location = $ToolSelectionPageForm.Location; StartPosition = "Manual"; Size = $ToolSelectionPageForm.Size; MinimumSize = $ToolSelectionPageForm.MinimumSize; WindowState = $ToolSelectionPageForm.WindowState; Text = "Export existing rules to PowerShell commands"} 
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar -Property @{Anchor = "Left"}
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ProgressBar)
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Hide()
            $StatusBar = $ExportExistingRulesToPowerShellCommandsStatusBar
            . GroupPoliciesWithExistingFirewallRules
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
        }
        foreach ($ExportExistingRulesToPowerShellCommands in $Script:GroupPoliciesWithExistingFirewallRules)
        { # Loop through GPOs and add to listbox 
            [void]$ExportExistingRulesToPowerShellCommandsGpoListBox.Items.Add($ExportExistingRulesToPowerShellCommands)
        }
        $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a rule to export"
        $DefaultPageCancelButton.Left = $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $ExportExistingRulesToPowerShellCommandsSaveAsButton.Left = $DefaultPageCancelButton.Left - $ExportExistingRulesToPowerShellCommandsSaveAsButton.Width - 5 
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsSaveAsButton)
        $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged({$ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState})
    $ExportExistingRulesToPowerShellCommandsBottomButtonPanel = New-Object -TypeName Windows.Forms.Panel -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog =  New-Object -TypeName System.Windows.Forms.SaveFileDialog
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog.Filter = "PowerShell script (*.ps1)|*.ps1|All files (*.*)|*.*"
    $ExportExistingRulesToPowerShellCommandsSaveAsButton = New-Object -TypeName Windows.Forms.Button -Property @{Text = "Save As"; Anchor = "Right"} 
    $ExportExistingRulesToPowerShellCommandsSaveAsButton.Add_Click(
    {
        if ($ExportExistingRulesToPowerShellCommandsSaveFileDialog.ShowDialog() -eq "OK")
        {
            $ProgressBar = New-Object -TypeName System.Windows.Forms.ProgressBar -Property @{Anchor = "Left"}
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ProgressBar)
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Hide()
            $GPOSession = Open-NetGPO -PolicyStore ("$DomainName\$($ExportExistingRulesToPowerShellCommandsGpoListBox.SelectedItem)")
            [array]$FirewallRules = Get-NetFirewallRule -GPOSession $GPOSession
            $RuleProgress = 1
            foreach ($FirewallRule in $FirewallRules)
            {
                $ProgressBar.Value = ($RuleProgress*(100/$FirewallRules.Count))
                $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Exporting rule $($FirewallRule.DisplayName)" 
                $RuleProgress ++
                $Command = @"
New-NetFirewallRule -GPOSession `$GPOSession
"@
                $Value = $FirewallRule.Name
                $Command += @"
 -Name "$Value"
"@
                $Value = $FirewallRule.DisplayName
                $Command += @"
 -DisplayName "$Value"
"@
                $Value = $FirewallRule.Description
                if ($Value -ne $null)
                {
                    $Command += @"
 -Description "$Value"
"@
                }
                $Value = $FirewallRule.Group
                if ($Value -ne $null)
                {
                    $Command += @"
 -Group "$Value"
"@
                }
                $Value = $FirewallRule.Enabled
                if ($Value -ne "True")
                {
                    $Command += @"
 -Enabled "$Value"
"@
                }
                $Value = $FirewallRule.Profile
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Profile "$Value"
"@
                }
                $Value = $FirewallRule.Platform
                if($Value -ne $null)
                {
                    $Value = $Value -join '","'
                    $Command += @"
 -Platform "$Value"
"@
                }
                $Value = $FirewallRule.Direction
                if ($Value -ne "Inbound")
                {
                    $Command += @"
 -Direction "$Value"
"@
                }
                $Value = $FirewallRule.Action
                if ($Value -ne "Allow")
                {
                    $Command += @"
 -Action "$Value"
"@
                }
                $Value = $FirewallRule.EdgeTraversalPolicy
                if ($Value -ne "Block")
                {
                    $Command += @"
 -EdgeTraversalPolicy "$Value"
"@
                }
                $Value = $FirewallRule.LooseSourceMapping
                if ($Value -ne $false)
                {
                    $Command += @"
 -LooseSourceMapping "$true"
"@
                }
                $Value = $FirewallRule.LocalOnlyMapping
                if ($Value -ne $false)
                {
                    $Command += @"
 -LocalOnlyMapping "$true"
"@
                }
                $Value = $FirewallRule.Owner
                if ($Value -ne $null)
                {
                    $Command += @"
 -Owner "$Value"
"@
                }  
                $Value = ($FirewallRule| Get-NetFirewallAddressFilter -GPOSession $GPOSession).RemoteAddress
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '","'
                    $Command += @"
 -RemoteAddress "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallAddressFilter -GPOSession $GPOSession).LocalAddress
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '","'
                    $Command += @"
 -LocalAddress "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Program
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Program "$Value"
"@
                } 
                $Value = ($FirewallRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package
                if ($Value -ne $null)
                {
                    $Command += @"
 -Package "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).Protocol
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Protocol "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).LocalPort
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '","'
                    $Command += @"
 -LocalPort "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).RemotePort
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '","'
                    $Command += @"
 -RemotePort "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).IcmpType
                if ($Value -ne "Any")
                {
                    $Value = $Value -join '","'
                    $Command += @"
 -IcmpType "$Value"
"@
                }
                $Value = ($FirewallRule| Get-NetFirewallPortFilter -GPOSession $GPOSession).DynamicTarget
                if ($Value -ne "Any")
                {
                    $Command += @"
 -DynamicTarget "$Value"
"@
                }         
                $Value = ($FirewallRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Service "$Value"
"@
                }
                [string[]]$Commands += $Command
                #($FirewallRule| Get-NetFirewallInterfaceFilter).InterfaceAlias
                #$FirewallRule| Get-NetFirewallInterfaceTypeFilter
                #$FirewallRule| Get-NetFirewallSecurityFilter
            }
            $Commands| Out-File $ExportExistingRulesToPowerShellCommandsSaveFileDialog.FileName
            Remove-Variable -Name "GPOSession" -Force -ErrorAction SilentlyContinue
            $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a policy to export."
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ExportExistingRulesToPowerShellCommandsGpoListBox = New-Object -TypeName System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $ExportExistingRulesToPowerShellCommandsGpoListBox.Add_DoubleClick({$ExportExistingRulesToPowerShellCommandsSaveAsButton.PerformClick()})
    $ExportExistingRulesToPowerShellCommandsStatusBar = New-Object -TypeName Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Select a policy to export."} 
    $ExportExistingRulesToPowerShellCommandsPanel = New-Object -TypeName Windows.Forms.Panel -Property @{AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
    $ExportExistingRulesToPowerShellCommandsPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsGpoListBox)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsBottomButtonPanel)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function MainThread
{
    $DomainName = $env:USERDNSDOMAIN
    $ToolSelectionPageForm = New-Object -TypeName Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; StartPosition = "CenterScreen"; Width = 800; Height = 450; MinimumSize = @{Width = 310; Height = 200}; Text = "Windows firewall tool selection"} 
    $ToolSelectionPageBottomButtonPanel = New-Object -TypeName Windows.Forms.Panel -Property @{Width = $ToolSelectionPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ToolSelectionPageCancelButton = New-Object -TypeName Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $ToolSelectionPageCancelButton.Left = $ToolSelectionPageBottomButtonPanel.Width - $ToolSelectionPageCancelButton.Width - 16
    $ToolSelectionPageForm.CancelButton = $ToolSelectionPageCancelButton
    $DefaultPageCancelButton = New-Object -TypeName Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $DefaultPageCancelButton.Add_Click(
    {
        if ($EditExistingFirewallRulesDataGridView.Parent)
        {
            #if ((. CancelAccept -Message "Are you sure, changes will be lost? (check button focus)" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "Cancel")
            #{
                #$ToolPageForm_FormClosing=[System.Windows.Forms.FormClosingEventHandler]{$_.Cancel = $true}
                $ToolSelectionPageForm.Size = $ToolPageForm.Size; $ToolSelectionPageForm.Location = $ToolPageForm.Location; $ToolSelectionPageForm.Show()
            #}
            #else
            #{
            #$ToolSelectionPageForm.Size = $ToolPageForm.Size; $ToolSelectionPageForm.Location = $ToolPageForm.Location; $ToolSelectionPageForm.Show()
            #}
            Write-Host "Default page cancel button"
        }
        else
        {
            $ToolSelectionPageForm.Size = $ToolPageForm.Size; $ToolSelectionPageForm.Location = $ToolPageForm.Location; $ToolSelectionPageForm.Show()
        }
    })
    $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
    [int]$FontSize = $SquareRootOfFormSize/40
    [int]$Margin = $SquareRootOfFormSize/20
    [int]$Padding = $SquareRootOfFormSize/125
    $ToolButtonPanel = New-Object -TypeName Windows.Forms.FlowLayoutPanel -Property @{BackColor = "WhiteSmoke"; AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolSelectionPageForm.Width - 16; Height = $ToolSelectionPageForm.Height - 82; FlowDirection = "LeftToRight"}
    $ToolButtonPanel.Add_SizeChanged(
    {
        $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
        [int]$FontSize = $SquareRootOfFormSize/40
        [int]$Margin = $SquareRootOfFormSize/20
        [int]$Padding = $SquareRootOfFormSize/125
        $BoldButtonFont = New-Object -TypeName System.Drawing.Font("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold)
        $ExportExistingRulesToPowerShellCommandsButton.Font = $BoldButtonFont
        $ExportExistingRulesToPowerShellCommandsButton.Margin = $Margin
        $ExportExistingRulesToPowerShellCommandsButton.Padding = $Padding
        $FindAllPoliciesWithFirewallRulesButton.Font = $BoldButtonFont
        $FindAllPoliciesWithFirewallRulesButton.Margin = $Margin
        $FindAllPoliciesWithFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $UpdateDomainResourcesButton.Font = $BoldButtonFont
        $UpdateDomainResourcesButton.Margin = $Margin
        $UpdateDomainResourcesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $EditExistingFirewallRulesButton.Font = $BoldButtonFont
        $EditExistingFirewallRulesButton.Margin = $Margin
        $EditExistingFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $ScanComputerForBlockedConnectionsButton.Font = $BoldButtonFont
        $ScanComputerForBlockedConnectionsButton.Margin = $Margin
        $ScanComputerForBlockedConnectionsButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
    })
    $BoldButtonFont = New-Object -TypeName System.Drawing.Font("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold) 
    $ExportExistingRulesToPowerShellCommandsButton = New-Object -TypeName Windows.Forms.Button -Property @{Margin = $Margin; Padding = $Padding; Width = 270; Height = 84; AutoSize = $true;AutoSizeMode = "GrowAndShrink"; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $ExportExistingRulesToPowerShellCommandsButton.Text = "Export existing`n rules to`nPowerShell commands" # As this button contains the most text all other buttons will inherit it's size
    $ExportExistingRulesToPowerShellCommandsButton.Add_Click({$ToolSelectionPageForm.Hide(); . ExportExistingRulesToPowerShellCommandsPage})
    $ExportExistingRulesToPowerShellCommandsToolTip = New-Object -TypeName System.Windows.Forms.ToolTip
    $ExportExistingRulesToPowerShellCommandsToolTip.SetToolTip($ExportExistingRulesToPowerShellCommandsButton, "Use this tool to query a domain for policies`nthat have existing firewall rules and then`nexport a policy to a PowerShell script.`n100% complete.")
    $FindAllPoliciesWithFirewallRulesButton = New-Object -TypeName Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $FindAllPoliciesWithFirewallRulesButton.Text = "Find all policies with firewall rules"
    $FindAllPoliciesWithFirewallRulesButton.Add_Click({$ToolSelectionPageForm.Hide(); . FindAllPoliciesWithFirewallRulesPage})
    $FindAllPoliciesWithFirewallRulesToolTip = New-Object -TypeName System.Windows.Forms.ToolTip
    $FindAllPoliciesWithFirewallRulesToolTip.SetToolTip($FindAllPoliciesWithFirewallRulesButton, "Use this tool to query a domain for policies`nthat have existing firewall rules, this list`ncan then be saved to a text file as reference.`n100% complete.")
    $UpdateDomainResourcesButton = New-Object -TypeName Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $UpdateDomainResourcesButton.Text = "  Update domain resources"
    $UpdateDomainResourcesButton.Add_Click({. UpdateDomainResourcesPage})
    $UpdateDomainResourcesToolTip = New-Object -TypeName System.Windows.Forms.ToolTip -Property @{AutoPopDelay = 7500}
    $UpdateDomainResourcesToolTip.SetToolTip($UpdateDomainResourcesButton, "Use this tool to update domain resources that can be used`nto create or update firewall rules in group policy objects.`nNames can be used and will be translated into IP addresses`nwhich can be applied to multiple rules.`n25% complete.")
    $EditExistingFirewallRulesButton = New-Object -TypeName Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $EditExistingFirewallRulesButton.Text = "Edit existing firewall rules"
    $EditExistingFirewallRulesButton.Add_Click({$ToolSelectionPageForm.Hide(); . EditExistingFirewallRulesPage})
    $EditExistingFirewallRulesToolTip = New-Object -TypeName System.Windows.Forms.ToolTip -Property @{AutoPopDelay = 7500}
    $EditExistingFirewallRulesToolTip.SetToolTip($EditExistingFirewallRulesButton, "Use this tool to edit existing firewall rules, domain resources can be`nselected and DNS will be used to resolve all IP addresses to be used.`nMultiple rules can be edited at once and saved to a PowerShell`nscript or saved back to the domain.`n60% complete.")
    $ScanComputerForBlockedConnectionsButton = New-Object -TypeName Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $ScanComputerForBlockedConnectionsButton.Text = "Scan computer for blocked connections"
    $ScanComputerForBlockedConnectionsButton.Add_Click({$ToolSelectionPageForm.Hide(); . ScanComputerForBlockedConnectionsPage})
    $ScanComputerForBlockedConnectionsToolTip = New-Object -TypeName System.Windows.Forms.ToolTip
    $ScanComputerForBlockedConnectionsToolTip.SetToolTip($ScanComputerForBlockedConnectionsButton, "Use this tool to scan a computer for blocked network`nconnections and to create new firewall rules that can be`nsaved to a PowerShell script or saved to a group policy object.`n65% complete.")
    $ToolSelectionPageStatusBar = New-Object -TypeName Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Please select a tool to launch."}
    $ToolSelectionPageBottomButtonPanel.Controls.Add($ToolSelectionPageCancelButton)
    $ToolButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsButton)
    $ToolButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesButton)
    $ToolButtonPanel.Controls.Add($UpdateDomainResourcesButton)
    $ToolButtonPanel.Controls.Add($EditExistingFirewallRulesButton)
    $ToolButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsButton)
    $ToolSelectionPageForm.Controls.Add($ToolButtonPanel) 
    $ToolSelectionPageForm.Controls.Add($ToolSelectionPageBottomButtonPanel) 
    $ToolSelectionPageForm.Controls.Add($ToolSelectionPageStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolSelectionPageForm.ShowDialog()
}
MainThread
