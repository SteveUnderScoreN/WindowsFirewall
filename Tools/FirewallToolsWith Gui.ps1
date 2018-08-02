<#
.NOTES
    EXPORT-FIREWALLRULESFROMPOLICY
    If a policy is created from the output of this script and that policy is linked to the same OU as the source policy the link order will determine which rule is applied.
    Because the GUID is copied from the source they are not unique across policies, under normal conditions both rules with the same display name would be applied but
    because they conflict the policy higher in the link order will have it's rule applied and that will overwrite the lower policy rule.
.NOTES
    Build 1808.1
#>

if ((Get-Host).Name -eq "ServerRemoteHost" -or $PSVersionTable.PSEdition -eq "Core")
{
    Write-Warning "This script invokes a GUI and cannot be run over a remot session or on PowerShell Core editions)"
    break
}
Add-Type -Assembly System.Windows.Forms
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
    Write-Progress -Activity "Searching group policy objects" -Completed
    Remove-Variable GroupPolicyObjectIndex
    $Script:GroupPoliciesWithExistingFirewallRules = $Script:GroupPoliciesWithExistingFirewallRules| Sort-Object
}

function GetComputerFileSystemVariables
{
    $DriveLetters = Invoke-Command -Session $ComputerPsSession -ScriptBlock {(Get-WmiObject Win32_Volume).DriveLetter}
    $ProgramFiles = Invoke-Command -Session $ComputerPsSession -ScriptBlock {$env:ProgramFiles}
    $ProgramFilesX86 = Invoke-Command -Session $ComputerPsSession -ScriptBlock {${env:ProgramFiles(x86)}}
    $SystemRoot = Invoke-Command -Session $ComputerPsSession -ScriptBlock {$env:SystemRoot}
}

function FindAllPoliciesWithFirewallRulesPage
{
    $FindAllPoliciesWithFirewallRulesForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; StartPosition = "CenterScreen"; Width = 800; Height = 450; MinimumSize = $ToolPageForm.MinimumSize; WindowState = $ToolPageForm.WindowState; Text = "Find all policies with firewall rules"} 
    $FindAllPoliciesWithFirewallRulesForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object System.Windows.Forms.ProgressBar -Property @{Anchor = "Left"}
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
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesCancelButton)
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesSaveAsButton)
        $FindAllPoliciesWithFirewallRulesGpoListBox.Show()
        Write-Host "Shown triggered" $FindAllPoliciesWithFirewallRulesForm.Visible
    })
    $FindAllPoliciesWithFirewallRulesBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $FindAllPoliciesWithFirewallRulesForm.Width; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $FindAllPoliciesWithFirewallRulesSaveFileDialog =  New-Object System.Windows.Forms.SaveFileDialog
    $FindAllPoliciesWithFirewallRulesSaveFileDialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
    $FindAllPoliciesWithFirewallRulesCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $FindAllPoliciesWithFirewallRulesCancelButton.Left = $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Width - $FindAllPoliciesWithFirewallRulesCancelButton.Width - 16
    $FindAllPoliciesWithFirewallRulesCancelButton.Add_Click({$ToolPageForm.Show()}) 
    $FindAllPoliciesWithFirewallRulesSaveAsButton = New-Object Windows.Forms.Button -Property @{Text = "Save As"; Anchor = "Right"} 
    $FindAllPoliciesWithFirewallRulesSaveAsButton.Left = $FindAllPoliciesWithFirewallRulesCancelButton.Left - $FindAllPoliciesWithFirewallRulesSaveAsButton.Width - 5 
    $FindAllPoliciesWithFirewallRulesSaveAsButton.Add_Click(
    {
        if ($FindAllPoliciesWithFirewallRulesSaveFileDialog.ShowDialog() -eq "OK")
        {
            $FindAllPoliciesWithFirewallRulesGpoListBox.Items| Out-File -FilePath $FindAllPoliciesWithFirewallRulesSaveFileDialog.FileName
        }
    })
    $FindAllPoliciesWithFirewallRulesForm.CancelButton = $FindAllPoliciesWithFirewallRulesCancelButton
    $FindAllPoliciesWithFirewallRulesGpoListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $FindAllPoliciesWithFirewallRulesStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Scanning policies."} 
    $FindAllPoliciesWithFirewallRulesPanel = New-Object Windows.Forms.Panel -Property @{AutoScroll = $true; Anchor = "Top, Bottom, Left, Right"; Width = $FindAllPoliciesWithFirewallRulesForm.Width - 16; Height = $FindAllPoliciesWithFirewallRulesForm.Height - 82}
    $FindAllPoliciesWithFirewallRulesPanel.Controls.Add($FindAllPoliciesWithFirewallRulesGpoListBox)
    $FindAllPoliciesWithFirewallRulesForm.Controls.Add($FindAllPoliciesWithFirewallRulesPanel) # Added to the form first to set focus on this panel
    $FindAllPoliciesWithFirewallRulesForm.Controls.Add($FindAllPoliciesWithFirewallRulesBottomButtonPanel)
    $FindAllPoliciesWithFirewallRulesForm.Controls.Add($FindAllPoliciesWithFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    $FindAllPoliciesWithFirewallRulesForm.ShowDialog()| Out-Null
}

function UpdateDomainResourcesPage
{
    $ToolPageStatusBar.Text = "Tool not available in this build."; Start-Sleep -Milliseconds 400; $ToolPageStatusBar.Text = "Please select a tool to launch."
}

function EditExistingFirewallRulesPage
{
    $EditExistingFirewallRulesForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; StartPosition = "CenterScreen"; Width = 800; Height = 450; MinimumSize = $ToolPageForm.MinimumSize; WindowState = $ToolPageForm.WindowState; Text = "Edit existing firewall rules"} 
    $EditExistingFirewallRulesForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object System.Windows.Forms.ProgressBar -Property @{Anchor = "Left"}
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
        $EditExistingFirewallRulesGpoListBox.Show()
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesCancelButton)
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesAcceptButton)
        Write-Host "Shown triggered" $EditExistingFirewallRulesForm.Visible
    })
    $EditExistingFirewallRulesBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $EditExistingFirewallRulesForm.Width; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $EditExistingFirewallRulesCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $EditExistingFirewallRulesCancelButton.Left = $EditExistingFirewallRulesBottomButtonPanel.Width - $EditExistingFirewallRulesCancelButton.Width - 16
    $EditExistingFirewallRulesCancelButton.Add_Click({$ToolPageForm.Show()}) 
    $EditExistingFirewallRulesAcceptButton = New-Object Windows.Forms.Button -Property @{Text = "Select"; Anchor = "Right"} 
    $EditExistingFirewallRulesAcceptButton.Left = $EditExistingFirewallRulesCancelButton.Left - $EditExistingFirewallRulesAcceptButton.Width - 5
    $EditExistingFirewallRulesForm.CancelButton = $EditExistingFirewallRulesCancelButton
    $EditExistingFirewallRulesForm.AcceptButton = $EditExistingFirewallRulesAcceptButton
    $EditExistingFirewallRulesGpoListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesGpoListBox.Add_DoubleClick(
    {
        foreach ($EditExistingFirewallRulesRule in (Get-NetFirewallRule -PolicyStore ("$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)")).DisplayName) #Use a [array]GPOSession
        {
            $EditExistingFirewallRulesRulesListBox.Items.Add($EditExistingFirewallRulesRule)
        }
        $EditExistingFirewallRulesRulesListBox.SelectionMode = "MultiExtended"
        $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesGpoListBox)
        $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
        $EditExistingFirewallRulesStatusBar.Text = "Please select one or more rules to display."
    })
    $EditExistingFirewallRulesRulesListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesRulesListBox.Add_DoubleClick(
    {
        $EditExistingFirewallRulesStatusBar.Text = "Function not available in this build."; Start-Sleep -Milliseconds 400; $EditExistingFirewallRulesStatusBar.Text = "Please select one or more rules to display."    
        # Firewall rule builder - class - Get-Net... into array
        # Firewall rule editor - DataGridView with UpdateDataSourceForComboBoxCell
    })
    $EditExistingFirewallRulesRuleSettingsListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesRuleSettingsListBox.Add_DoubleClick(
    {
        Write-Host $EditExistingFirewallRulesRuleSettingsListBox.SelectedItem
    })
    $EditExistingFirewallRulesStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Please select a GPO to display."} 
    $EditExistingFirewallRulesPanel = New-Object Windows.Forms.Panel -Property @{AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $EditExistingFirewallRulesForm.Width - 16; Height = $EditExistingFirewallRulesForm.Height - 82}
    $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
    $EditExistingFirewallRulesForm.Controls.Add($EditExistingFirewallRulesPanel) # Added to the form first to set focus on this panel
    $EditExistingFirewallRulesForm.Controls.Add($EditExistingFirewallRulesBottomButtonPanel)
    $EditExistingFirewallRulesForm.Controls.Add($EditExistingFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    $EditExistingFirewallRulesForm.ShowDialog()| Out-Null
}

function ScanComputerForBlockedConnectionsPage
{
    $ScanComputerForBlockedConnectionsForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "FixedDialog" ; StartPosition = "CenterScreen"; Width = 250; Height = 110; Text = "Scan computer for blocked connections"; MaximizeBox = $false; MinimizeBox = $false; ControlBox = $false}
    $ScanComputerForBlockedConnectionsBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ScanComputerForBlockedConnectionsForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ScanComputerForBlockedConnectionsCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Cancel"; Anchor = "Right"}
    $ScanComputerForBlockedConnectionsCancelButton.Left = $ScanComputerForBlockedConnectionsBottomButtonPanel.Width - $ScanComputerForBlockedConnectionsCancelButton.Width - 5
    $ScanComputerForBlockedConnectionsCancelButton.Add_Click({$ToolPageForm.Show()}) 
    $ScanComputerForBlockedConnectionsAcceptButton = New-Object Windows.Forms.Button -Property @{Text = "Scan"; Anchor = "Right"} 
    $ScanComputerForBlockedConnectionsAcceptButton.Left = $ScanComputerForBlockedConnectionsCancelButton.Left - $ScanComputerForBlockedConnectionsAcceptButton.Width - 5
    $ScanComputerForBlockedConnectionsAcceptButton.Add_Click(
    {
        $Computer = $ScanComputerForBlockedConnectionsTextBox.Text
        class NetworkConnection
        {
            [int] $ProcessID
            [string] $Application
            [string] $Direction
            [ipaddress] $SourceAddress
            [int] $SourcePort
            [ipaddress] $DestAddress
            [int] $DestPort
            [string] $Protocol
        }
        try
        {
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Scanning $Computer."
            [datetime]$NetworkStateChange =  (Get-WinEvent -ComputerName $Computer -FilterHashTable @{LogName = "Microsoft-Windows-NetworkProfile/Operational"; ID = 4004} -MaxEvents 1 -ErrorAction Stop).TimeCreated.AddSeconds("1")        
            $Events = (Get-WinEvent -ComputerName $Computer -FilterHashTable @{LogName = "Security"; ID = 5157; StartTime = $NetworkStateChange} -ErrorAction Stop) #Can these commands be run in the CIM session
            if($null -eq $Events)
            {
                Write-Host "No matching events were found since the last network state change on $NetworkStateChange, event ID 4004 in log 'Microsoft-Windows-NetworkProfile/Operational'"
                # I need a message function with just an OK button that takes a message parameter
            }
            else
            {
                [xml[]]$Events = $Events.ToXml()
                $ComputerCimSession = New-CimSession -ComputerName $Computer
                $RunningSvchostServices = Get-CimInstance -CimSession $ComputerCimSession -Class "Win32_Service" -Filter "PathName LIKE '%svchost.exe%' AND State = 'Running'"
                $RunningServices = Get-CimInstance -CimSession $ComputerCimSession -Class "Win32_Service" -Filter "State = 'Running'"
                $ComputerCimSession| Remove-CimSession
                $ComputerPsSession = New-PSSession -ComputerName $Computer
                . GetComputerFileSystemVariables 
                [array]$AdHarvest = Invoke-Command -Session $ComputerPsSession -ScriptBlock {(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ADHarvest\" -Name "LastFetchContents").LastFetchContents.Split(",")}
                #$AdHarvest.Count
                $ComputerPsSession| Remove-PSSession
                [NetworkConnection[]]$InboundNetworkConnections = @()
                [NetworkConnection[]]$OutboundNetworkConnections = @()
                foreach ($Event in $Events)
                {
                    #if (($Event.Event.EventData.Data.Where({$_.Name -EQ "Application"})).'#text' -like "\device\harddiskvolume*")
                    #    {
                    #        $HardDiskVolume = ((Select-String -InputObject (($Event.Event.EventData.Data.Where({$_.Name -EQ "Application"})).'#text') -Pattern '\\device\\harddiskvolume') -split("\\"))[2].TrimStart("harddiskvolume")
                    #        $Drive = (Get-Variable -Name HardDiskVolume$HardDiskVolume).Value
                    #    }
                    $NetworkConnection = New-Object -TypeName "NetworkConnection"
                    $NetworkConnection.ProcessID = ($Event.Event.EventData.Data.Where({$_.Name -EQ "ProcessID"})).'#text'
                    $NetworkConnection.Application = ($Event.Event.EventData.Data.Where({$_.Name -EQ "Application"})).'#text' -replace "\\device\\harddiskvolume\d+\\windows\\","%SystemRoot%\"  # -replace "\\device\\harddiskvolume\d+","$Drive" - Will need to search remote drives to populate the HarddiskVolume variables.
                    $NetworkConnection.Direction = (($Event.Event.EventData.Data.Where({$_.Name -EQ "Direction"})).'#text') -replace "%%14593","Outbound" -replace "%%14592","Inbound"
                    $NetworkConnection.SourceAddress = ($Event.Event.EventData.Data.Where({$_.Name -EQ "SourceAddress"})).'#text'
                    $NetworkConnection.SourcePort = ($Event.Event.EventData.Data.Where({$_.Name -EQ "SourcePort"})).'#text'
                    $NetworkConnection.DestAddress = ($Event.Event.EventData.Data.Where({$_.Name -EQ "DestAddress"})).'#text'
                    $NetworkConnection.DestPort = ($Event.Event.EventData.Data.Where({$_.Name -EQ "DestPort"})).'#text'
                    $NetworkConnection.Protocol = (($Event.Event.EventData.Data.Where({$_.Name -EQ "Protocol"})).'#text') -replace "^1$","ICMPv4" -replace "^6$","TCP" -replace "^17$","UDP" -replace "^58$","ICMPv6"
                    if ($NetworkConnection.Direction -eq "Inbound")
                    {
                        $InboundNetworkConnections += $NetworkConnection
                    }
                    else
                    {
                        $OutboundNetworkConnections += $NetworkConnection
                    }
                }
                $FilteredOutboundNetworkConnections = $OutboundNetworkConnections| Select-Object -Property * -ExcludeProperty "Direction","SourcePort" -Unique| Out-GridView
                $FilteredInboundNetworkConnections = $InboundNetworkConnections| Select-Object -Property * -ExcludeProperty "Direction","DestPort" -Unique| Out-GridView
            }
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
        }
        catch
        {
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Scan failed."; Start-Sleep -Milliseconds 400; $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
        }
    })
    $ScanComputerForBlockedConnectionsForm.CancelButton = $ScanComputerForBlockedConnectionsCancelButton
    $ScanComputerForBlockedConnectionsForm.AcceptButton = $ScanComputerForBlockedConnectionsAcceptButton
    $ScanComputerForBlockedConnectionsTextBox = New-Object Windows.Forms.TextBox -Property @{width = $ScanComputerForBlockedConnectionsForm.Width - 36; Location = @{X = 10; Y= 5}; Text = "LocalHost"}
    $ScanComputerForBlockedConnectionsStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Enter a computer name or IP address to scan."}
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsCancelButton)
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsAcceptButton)
    $ScanComputerForBlockedConnectionsForm.Controls.Add($ScanComputerForBlockedConnectionsTextBox)
    $ScanComputerForBlockedConnectionsForm.Controls.Add($ScanComputerForBlockedConnectionsBottomButtonPanel)
    $ScanComputerForBlockedConnectionsForm.Controls.Add($ScanComputerForBlockedConnectionsStatusBar) 
    $ScanComputerForBlockedConnectionsForm.ShowDialog()| Out-Null
}

function ExportExistingRulesToPowerShellCommandsPage
{
    $ExportExistingRulesToPowerShellCommandsForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; StartPosition = "CenterScreen"; Width = 800; Height = 450; MinimumSize = $ToolPageForm.MinimumSize; WindowState = $ToolPageForm.WindowState; Text = "Export existing rules to PowerShell commands"} 
    $ExportExistingRulesToPowerShellCommandsForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object System.Windows.Forms.ProgressBar -Property @{Anchor = "Left"}
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
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsCancelButton)
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsSaveAsButton)
        $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
    })
    $ExportExistingRulesToPowerShellCommandsBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ExportExistingRulesToPowerShellCommandsForm.Width; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog =  New-Object System.Windows.Forms.SaveFileDialog
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog.Filter = "PowerShell script (*.ps1)|*.ps1|All files (*.*)|*.*"
    $ExportExistingRulesToPowerShellCommandsCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $ExportExistingRulesToPowerShellCommandsCancelButton.Left = $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Width - $ExportExistingRulesToPowerShellCommandsCancelButton.Width - 16
    $ExportExistingRulesToPowerShellCommandsCancelButton.Add_Click({$ToolPageForm.Show()}) 
    $ExportExistingRulesToPowerShellCommandsSaveAsButton = New-Object Windows.Forms.Button -Property @{Text = "Save As"; Anchor = "Right"} 
    $ExportExistingRulesToPowerShellCommandsSaveAsButton.Left = $ExportExistingRulesToPowerShellCommandsCancelButton.Left - $ExportExistingRulesToPowerShellCommandsSaveAsButton.Width - 5 
    $ExportExistingRulesToPowerShellCommandsSaveAsButton.Add_Click(
    {
        if ($ExportExistingRulesToPowerShellCommandsSaveFileDialog.ShowDialog() -eq "OK")
        {
            $ProgressBar = New-Object System.Windows.Forms.ProgressBar -Property @{Anchor = "Left"}
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ProgressBar)
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Hide()
            $GPOSession = Open-NetGPO -PolicyStore ("$DomainName\$($ExportExistingRulesToPowerShellCommandsGpoListBox.SelectedItem)")
            [array]$FirewallRules = Get-NetFirewallRule -GPOSession $GPOSession
            $RuleProgress = 1
            foreach ($FirewallRule in $FirewallRules)
            {
                $ProgressBar.Value = ($RuleProgress*(100/$FirewallRules.Count)) # Was -PercentComplete (($RuleProgress/$NumberOfFirewallRules)*100)
                $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Exporting rule $($FirewallRule.DisplayName)" 
                $RuleProgress ++
                $Command = @"
New-NetFirewallRule -GPOSession `$GPOSession
"@
                $Value = $FirewallRule.InstanceID
                $Command += @"
 -Name "$Value"
"@
                $Value = $FirewallRule.ElementName
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
            Remove-Variable GPOSession
            $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a policy to export."
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
            #$ExportExistingRulesToPowerShellCommandsGpoListBox.Items| Out-File -FilePath $ExportExistingRulesToPowerShellCommandsSaveFileDialog.FileName
        }
    })
    $ExportExistingRulesToPowerShellCommandsForm.CancelButton = $ExportExistingRulesToPowerShellCommandsCancelButton
    $ExportExistingRulesToPowerShellCommandsGpoListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $ExportExistingRulesToPowerShellCommandsGpoListBox.Add_DoubleClick({$ExportExistingRulesToPowerShellCommandsSaveAsButton.PerformClick()})
    $ExportExistingRulesToPowerShellCommandsStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Select a policy to export."} 
    $ExportExistingRulesToPowerShellCommandsPanel = New-Object Windows.Forms.Panel -Property @{AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ExportExistingRulesToPowerShellCommandsForm.Width - 16; Height = $ExportExistingRulesToPowerShellCommandsForm.Height - 82}
    $ExportExistingRulesToPowerShellCommandsPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsGpoListBox)
    $ExportExistingRulesToPowerShellCommandsForm.Controls.Add($ExportExistingRulesToPowerShellCommandsPanel) # Added to the form first to set focus on this panel
    $ExportExistingRulesToPowerShellCommandsForm.Controls.Add($ExportExistingRulesToPowerShellCommandsBottomButtonPanel)
    $ExportExistingRulesToPowerShellCommandsForm.Controls.Add($ExportExistingRulesToPowerShellCommandsStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    $ExportExistingRulesToPowerShellCommandsForm.ShowDialog()| Out-Null
}

function MainThread
{
    $DomainName = $env:USERDNSDOMAIN
    $ToolPageForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; StartPosition = "CenterScreen"; Width = 800; Height = 450; MinimumSize = New-Object Drawing.Size @(310,200); Text = "Windows firewall tool selection"} 
    $ToolPageBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ToolPageForm.Width; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ToolPageCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $ToolPageCancelButton.Left = $ToolPageBottomButtonPanel.Width - $ToolPageCancelButton.Width - 16
    $ToolPageForm.CancelButton = $ToolPageCancelButton
    $SquareRootOfFormSize = [math]::Sqrt($ToolPageForm.Width * $ToolPageForm.Height)
    [int]$FontSize = $SquareRootOfFormSize/35
    [int]$Margin = $SquareRootOfFormSize/20
    [int]$Padding = $SquareRootOfFormSize/125
    $ToolButtonPanel = New-Object Windows.Forms.FlowLayoutPanel -Property @{BackColor = "WhiteSmoke"; AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
    $ToolButtonPanel.Add_SizeChanged(
    {
        $SquareRootOfFormSize = [math]::Sqrt($ToolPageForm.Width * $ToolPageForm.Height)
        [int]$FontSize = $SquareRootOfFormSize/30
        [int]$Margin = $SquareRootOfFormSize/20
        [int]$Padding = $SquareRootOfFormSize/125
        $BoldButtonFont = New-Object System.Drawing.Font("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold)
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
    $BoldButtonFont = New-Object System.Drawing.Font("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold) 
    $ExportExistingRulesToPowerShellCommandsButton = New-Object Windows.Forms.Button -Property @{Margin = New-Object Windows.Forms.Padding @($Margin); Padding = New-Object Windows.Forms.Padding @($Padding); Width = 270; Height = 84; AutoSize = $true;AutoSizeMode = "GrowAndShrink"; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $ExportExistingRulesToPowerShellCommandsButton.Text = "Export existing`n rules to`nPowerShell commands" # As this button contains the most text all other buttons will inherit it's size
    $ExportExistingRulesToPowerShellCommandsButton.Add_Click({$ToolPageForm.Hide(); . ExportExistingRulesToPowerShellCommandsPage})
    $FindAllPoliciesWithFirewallRulesButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $FindAllPoliciesWithFirewallRulesButton.Text = "Find all policies with firewall rules"
    $FindAllPoliciesWithFirewallRulesButton.Add_Click({$ToolPageForm.Hide(); . FindAllPoliciesWithFirewallRulesPage})
    $UpdateDomainResourcesButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $UpdateDomainResourcesButton.Text = "  Update domain resources"
    $UpdateDomainResourcesButton.Add_Click({. UpdateDomainResourcesPage})
    $EditExistingFirewallRulesButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $EditExistingFirewallRulesButton.Text = "Edit existing firewall rules"
    $EditExistingFirewallRulesButton.Add_Click({$ToolPageForm.Hide(); . EditExistingFirewallRulesPage})
    $ScanComputerForBlockedConnectionsButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $ScanComputerForBlockedConnectionsButton.Text = "Scan computer for blocked connections"
    $ScanComputerForBlockedConnectionsButton.Add_Click({$ToolPageForm.Hide(); . ScanComputerForBlockedConnectionsPage})
    $ToolPageStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Please select a tool to launch."}
    $ToolPageBottomButtonPanel.Controls.Add($ToolPageCancelButton)
    $ToolButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsButton)
    $ToolButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesButton)
    $ToolButtonPanel.Controls.Add($UpdateDomainResourcesButton)
    $ToolButtonPanel.Controls.Add($EditExistingFirewallRulesButton)
    $ToolButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsButton)
    $ToolPageForm.Controls.Add($ToolButtonPanel) 
    $ToolPageForm.Controls.Add($ToolPageBottomButtonPanel) 
    $ToolPageForm.Controls.Add($ToolPageStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    $ToolPageForm.ShowDialog()| Out-Null
}
. MainThread
