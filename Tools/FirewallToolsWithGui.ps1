<#
.NOTES
    ExportExistingRulesToPowerShellCommands
        If a policy is created from the output of this script and that policy is linked to the same OU as the source policy the link order will determine which rule is applied.
        Because the GUID is copied from the source they are not unique across policies, under normal conditions both rules with the same display name would be applied but
        because they conflict the policy higher in the link order will have it's rule applied and that will overwrite the lower policy rule.
    Build 1808.7
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
    Remove-Variable -Name "GroupPolicyObjectIndex" -Force -ErrorAction SilentlyContinue
    $Script:GroupPoliciesWithExistingFirewallRules = $Script:GroupPoliciesWithExistingFirewallRules| Sort-Object
}

function GetComputerFileSystemVariables
{
    $DriveLetters = Invoke-Command -Session $ComputerPsSession -ScriptBlock {(Get-WmiObject Win32_Volume).DriveLetter}
    $ProgramFiles = Invoke-Command -Session $ComputerPsSession -ScriptBlock {$env:ProgramFiles}
    $ProgramFilesX86 = Invoke-Command -Session $ComputerPsSession -ScriptBlock {${env:ProgramFiles(x86)}}
    $SystemRoot = Invoke-Command -Session $ComputerPsSession -ScriptBlock {$env:SystemRoot}
}

function PopUpMessage ($Message) # Need to use `r`n for newline
{
    $PopUpMessageForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "FixedDialog"; Location = @{X = ($ToolPageForm.Location.X + 25); Y = ($ToolPageForm.Location.Y + 25)};StartPosition = "Manual" ; MinimumSize = @{Width = 150; Height = 100}; MaximizeBox = $false; MinimizeBox = $false; ControlBox = $false; AutoScroll = $true}
    $PopUpMessageBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $PopUpMessageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $PopUpMessageAcceptButton = New-Object Windows.Forms.Button -Property @{Text = "OK"; Anchor = "Right"}
    $PopUpMessageAcceptButton.Add_Click({$PopUpMessageForm.Close()})
    $PopUpMessageAcceptButton.Left = $PopUpMessageBottomButtonPanel.Width - $PopUpMessageAcceptButton.Width - 5
    $PopUpMessageForm.CancelButton = $PopUpMessageAcceptButton
    $PopUpMessageForm.AcceptButton = $PopUpMessageAcceptButton
    $PopUpMessageTextBox = New-Object Windows.Forms.TextBox -Property @{Multiline = $true; BackColor = "GhostWhite"; ReadOnly = $true; Text = $Message; MinimumSize = @{Width = 141; Height = 70}; MaximumSize = @{Width = 500; Height = 500}}
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
    $CancelAcceptForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "FixedDialog"; Location = @{X = ($ToolPageForm.Location.X + 25); Y = ($ToolPageForm.Location.Y + 25)};StartPosition = "Manual" ; MinimumSize = @{Width = 200; Height = 100}; MaximizeBox = $false; MinimizeBox = $false; ControlBox = $false}
    $CancelAcceptForm.Add_Shown({$CancelAcceptAcceptButton.Focus()})
    $CancelAcceptBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $CancelAcceptForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $CancelAcceptCancelButton = New-Object Windows.Forms.Button -Property @{Text = $CancelButtonText; Anchor = "Right"}
    $CancelAcceptCancelButton.Left = $CancelAcceptBottomButtonPanel.Width - $CancelAcceptCancelButton.Width - 5
    $CancelAcceptAcceptButton = New-Object Windows.Forms.Button -Property @{Text = $AcceptButtonText; Anchor = "Right"}
    $CancelAcceptAcceptButton.Left = $CancelAcceptCancelButton.Left - $CancelAcceptAcceptButton.Width - 5
    $CancelAcceptAcceptButton.DialogResult = "OK"
    $CancelAcceptForm.CancelButton = $CancelAcceptCancelButton
    $CancelAcceptForm.AcceptButton = $CancelAcceptAcceptButton
    $CancelAcceptTextBox = New-Object Windows.Forms.TextBox -Property @{Multiline = $true; BackColor = "GhostWhite"; ReadOnly = $true; Text = $Message; MinimumSize = @{Width = 191; Height = 70}}
    $CancelAcceptTextBox.Size = $CancelAcceptTextBox.PreferredSize
    $CancelAcceptForm.Width = $CancelAcceptTextBox.Width + 9
    $CancelAcceptForm.Height = $CancelAcceptTextBox.Height + 30
    $CancelAcceptBottomButtonPanel.Controls.Add($CancelAcceptCancelButton)
    $CancelAcceptBottomButtonPanel.Controls.Add($CancelAcceptAcceptButton)
    $CancelAcceptForm.Controls.Add($CancelAcceptBottomButtonPanel)
    $CancelAcceptForm.Controls.Add($CancelAcceptTextBox)
    return $CancelAcceptForm.ShowDialog() 
}

function FindAllPoliciesWithFirewallRulesPage
{
    $ToolPageForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; Location = $ToolSelectionPageForm.Location; StartPosition = "Manual"; Width = $ToolSelectionPageForm.Width; Height = $ToolSelectionPageForm.Height; MinimumSize = $ToolSelectionPageForm.MinimumSize; WindowState = $ToolSelectionPageForm.WindowState; Text = "Find all policies with firewall rules"} 
    $ToolPageForm.Add_Shown(
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
        $DefaultPageCancelButton.Left = $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $FindAllPoliciesWithFirewallRulesSaveAsButton.Left = $DefaultPageCancelButton.Left - $FindAllPoliciesWithFirewallRulesSaveAsButton.Width - 5 
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($FindAllPoliciesWithFirewallRulesSaveAsButton)
        $FindAllPoliciesWithFirewallRulesGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged({$ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState})
    $FindAllPoliciesWithFirewallRulesBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $FindAllPoliciesWithFirewallRulesSaveFileDialog =  New-Object System.Windows.Forms.SaveFileDialog
    $FindAllPoliciesWithFirewallRulesSaveFileDialog.Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*"
    $FindAllPoliciesWithFirewallRulesSaveAsButton = New-Object Windows.Forms.Button -Property @{Text = "Save As"; Anchor = "Right"} 
    $FindAllPoliciesWithFirewallRulesSaveAsButton.Add_Click(
    {
        if ($FindAllPoliciesWithFirewallRulesSaveFileDialog.ShowDialog() -eq "OK")
        {
            $FindAllPoliciesWithFirewallRulesGpoListBox.Items| Out-File -FilePath $FindAllPoliciesWithFirewallRulesSaveFileDialog.FileName
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $FindAllPoliciesWithFirewallRulesGpoListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $FindAllPoliciesWithFirewallRulesStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Scanning policies."} 
    $FindAllPoliciesWithFirewallRulesPanel = New-Object Windows.Forms.Panel -Property @{AutoScroll = $true; Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
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
    $ToolPageForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; Location = $ToolSelectionPageForm.Location; StartPosition = "Manual"; Width = $ToolSelectionPageForm.Width; Height = $ToolSelectionPageForm.Height; MinimumSize = $ToolSelectionPageForm.MinimumSize; WindowState = $ToolSelectionPageForm.WindowState; Text = "Edit existing firewall rules";} 
    $ToolPageForm.Add_Shown(
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
        $DefaultPageCancelButton.Left = $EditExistingFirewallRulesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $EditExistingFirewallRulesAcceptButton.Left = $DefaultPageCancelButton.Left - $EditExistingFirewallRulesAcceptButton.Width - 5
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesAcceptButton)
        $EditExistingFirewallRulesGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged({$ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState})
    $EditExistingFirewallRulesBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $EditExistingFirewallRulesAcceptButton = New-Object Windows.Forms.Button -Property @{Text = "Select"; Anchor = "Right"} 
    $EditExistingFirewallRulesAcceptButton.Add_Click(
    {
        if ($EditExistingFirewallRulesGpoListBox.Parent)
        {
            foreach ($EditExistingFirewallRulesRule in (Get-NetFirewallRule -PolicyStore ("$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)")).DisplayName) #Use a [array]GPOSession
            {
                $EditExistingFirewallRulesRulesListBox.Items.Add($EditExistingFirewallRulesRule)
            }
            $EditExistingFirewallRulesRulesListBox.SelectionMode = "MultiExtended"
            $EditExistingFirewallRulesStatusBar.Text = "Please select one or more rules to display."
            $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesBackButton)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesGpoListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
            $EditExistingFirewallRulesRulesListBox.Focus()
        }
        elseif ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            . PopUpMessage -Message "Function not available in this build."
        }
        elseif ($EditExistingFirewallRulesRuleSettingsListBox.Parent)
        {
            . PopUpMessage -Message "Function not available in this build."   
        }
    })
    $EditExistingFirewallRulesBackButton = New-Object Windows.Forms.Button -Property @{Text = "Back"; Anchor = "Right"}
    $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
    $EditExistingFirewallRulesBackButton.Add_Click(
    {
        if ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Remove($EditExistingFirewallRulesBackButton)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRulesListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
        }
        elseif ($EditExistingFirewallRulesRuleSettingsListBox.Parent)
        {
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRuleSettingsListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ToolPageForm.AcceptButton = $EditExistingFirewallRulesAcceptButton
    $EditExistingFirewallRulesGpoListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesGpoListBox.Add_DoubleClick(
    {
       $EditExistingFirewallRulesAcceptButton.PerformClick()
    })
    $EditExistingFirewallRulesRulesListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesRulesListBox.Add_DoubleClick(
    {
        $EditExistingFirewallRulesAcceptButton.PerformClick()
        # Firewall rule builder - class - Get-Net... into array
        # Firewall rule editor - DataGridView with UpdateDataSourceForComboBoxCell
    })
    $EditExistingFirewallRulesRuleSettingsListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $EditExistingFirewallRulesRuleSettingsListBox.Add_DoubleClick(
    {
        $EditExistingFirewallRulesAcceptButton.PerformClick()
    })
    $EditExistingFirewallRulesStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Please select a GPO to display."} 
    $EditExistingFirewallRulesPanel = New-Object Windows.Forms.Panel -Property @{AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
    $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesBottomButtonPanel)
    $ToolPageForm.Controls.Add($EditExistingFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function ScanComputerForBlockedConnectionsPage
{
    $ToolPageForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "FixedDialog"; Location = @{X = ($ToolSelectionPageForm.Location.X + ($ToolSelectionPageForm.width/2)) - 125; Y = ($ToolSelectionPageForm.Location.Y + ($ToolSelectionPageForm.Height/2)) - 55}; StartPosition = "Manual"; Width = 250; Height = 110; Text = "Scan computer for blocked connections"; MaximizeBox = $false; MinimizeBox = $false; ControlBox = $false}
    $ScanComputerForBlockedConnectionsBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ScanComputerForBlockedConnectionsCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $ScanComputerForBlockedConnectionsCancelButton.Left = $ScanComputerForBlockedConnectionsBottomButtonPanel.Width - $ScanComputerForBlockedConnectionsCancelButton.Width - 5
    $ScanComputerForBlockedConnectionsCancelButton.Add_Click({$ToolSelectionPageForm.Show()}) 
    $ScanComputerForBlockedConnectionsAcceptButton = New-Object Windows.Forms.Button -Property @{Text = "Scan"; Anchor = "Right"} 
    $ScanComputerForBlockedConnectionsAcceptButton.Left = $ScanComputerForBlockedConnectionsCancelButton.Left - $ScanComputerForBlockedConnectionsAcceptButton.Width - 5
    $ScanComputerForBlockedConnectionsAcceptButton.Add_Click(
    {
        [String]$Computer = $ScanComputerForBlockedConnectionsTextBox.Text
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
            Remove-Variable -Name "JobNumber" -Force -ErrorAction SilentlyContinue
            Remove-Variable -Name "NetworkConnectivityJobs" -Force -ErrorAction SilentlyContinue
            foreach ($IpAddress in $IpAddresses) # Because Test-NetConnection does the IP addresses one after another, uses Ping and doesn't provide feedback during the test I've opted to use asynchronous TCP jobs and monitor for the state of those. This also allows me to abandon the jobs if the tests are taking too long.
            {
                $JobNumber += 1
                if ($IpAddress.AddressFamily -eq "InterNetworkV6")
                {
                    $TcpClient = New-Object System.Net.Sockets.TcpClient("InterNetworkV6")
                }
                else
                {
                    $TcpClient = New-Object System.Net.Sockets.TcpClient("InterNetwork")
                }
                New-Variable -Name ("NetworkConnectivityJobs" + "$JobNumber") -Value ($TcpClient.ConnectAsync($IpAddress,135))
                [array]$NetworkConnectivityJobs += Get-Variable -Name ("NetworkConnectivityJobs" + "$JobNumber")
            }
            $WaitTime = (Get-Date).AddSeconds(10)
            Remove-Variable -Name "NetworkConnectivityJobRanToCompletion" -Force -ErrorAction SilentlyContinue
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
                            Remove-Variable -Name "DiagnosticResults" -Force -ErrorAction SilentlyContinue
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
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Scanning $Computer."
            [datetime]$NetworkStateChange =  (Get-WinEvent -ComputerName $Computer -FilterHashTable @{LogName = "Microsoft-Windows-NetworkProfile/Operational"; ID = 4004} -MaxEvents 1 -ErrorAction Stop).TimeCreated.AddSeconds("1")        
            $Events = (Get-WinEvent -ComputerName $Computer -FilterHashTable @{LogName = "Security"; ID = 5157; StartTime = $NetworkStateChange} -ErrorAction Stop) #Can these commands be run in the CIM session
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
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
        }
        catch [System.Management.Automation.RuntimeException]
        {
            if ($error[0].Exception.Message -eq "Connectivity test aborted, scanning cancelled.")
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
                . PopUpMessage -Message "No matching events were found since the last network`r`nstate change on $NetworkStateChange, event ID 4004 in`r`nlog 'Microsoft-Windows-NetworkProfile/Operational'"
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
        $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
    })
    $ToolPageForm.CancelButton = $ScanComputerForBlockedConnectionsCancelButton
    $ToolPageForm.AcceptButton = $ScanComputerForBlockedConnectionsAcceptButton
    $ScanComputerForBlockedConnectionsTextBox = New-Object Windows.Forms.TextBox -Property @{width = $ToolPageForm.Width - 36; Location = @{X = 10; Y= 5}; Text = "LocalHost"}
    $ScanComputerForBlockedConnectionsStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Enter a computer name or IP address to scan."}
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsCancelButton)
    $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Add($ScanComputerForBlockedConnectionsAcceptButton)
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsTextBox)
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsBottomButtonPanel)
    $ToolPageForm.Controls.Add($ScanComputerForBlockedConnectionsStatusBar)
    [void]$ToolPageForm.ShowDialog()
}

function ExportExistingRulesToPowerShellCommandsPage
{
    $ToolPageForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; Location = $ToolSelectionPageForm.Location; StartPosition = "Manual"; Width = $ToolSelectionPageForm.Width; Height = $ToolSelectionPageForm.Height; MinimumSize = $ToolSelectionPageForm.MinimumSize; WindowState = $ToolSelectionPageForm.WindowState; Text = "Export existing rules to PowerShell commands"} 
    $ToolPageForm.Add_Shown(
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
        $DefaultPageCancelButton.Left = $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $ExportExistingRulesToPowerShellCommandsSaveAsButton.Left = $DefaultPageCancelButton.Left - $ExportExistingRulesToPowerShellCommandsSaveAsButton.Width - 5 
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsSaveAsButton)
        $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged({$ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState})
    $ExportExistingRulesToPowerShellCommandsBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ToolPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog =  New-Object System.Windows.Forms.SaveFileDialog
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog.Filter = "PowerShell script (*.ps1)|*.ps1|All files (*.*)|*.*"
    $ExportExistingRulesToPowerShellCommandsSaveAsButton = New-Object Windows.Forms.Button -Property @{Text = "Save As"; Anchor = "Right"} 
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
            Remove-Variable -Name "GPOSession" -Force -ErrorAction SilentlyContinue
            $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a policy to export."
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ExportExistingRulesToPowerShellCommandsGpoListBox = New-Object System.Windows.Forms.ListBox -Property @{AutoSize = $true; BackColor = "WhiteSmoke"; Dock = "Fill"}
    $ExportExistingRulesToPowerShellCommandsGpoListBox.Add_DoubleClick({$ExportExistingRulesToPowerShellCommandsSaveAsButton.PerformClick()})
    $ExportExistingRulesToPowerShellCommandsStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Select a policy to export."} 
    $ExportExistingRulesToPowerShellCommandsPanel = New-Object Windows.Forms.Panel -Property @{AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolPageForm.Width - 16; Height = $ToolPageForm.Height - 82}
    $ExportExistingRulesToPowerShellCommandsPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsGpoListBox)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsBottomButtonPanel)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function MainThread
{
    $DomainName = $env:USERDNSDOMAIN
    $ToolSelectionPageForm = New-Object Windows.Forms.Form -Property @{FormBorderStyle = "Sizable"; StartPosition = "CenterScreen"; Width = 800; Height = 450; MinimumSize = @{Width = 310; Height = 200}; Text = "Windows firewall tool selection"} 
    $ToolSelectionPageBottomButtonPanel = New-Object Windows.Forms.Panel -Property @{Width = $ToolSelectionPageForm.Width - 16; Height = 22; Dock = "Bottom"; BackColor = "WhiteSmoke"}
    $ToolSelectionPageCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $ToolSelectionPageCancelButton.Left = $ToolSelectionPageBottomButtonPanel.Width - $ToolSelectionPageCancelButton.Width - 16
    $ToolSelectionPageForm.CancelButton = $ToolSelectionPageCancelButton
    $DefaultPageCancelButton = New-Object Windows.Forms.Button -Property @{Text = "Exit"; Anchor = "Right"}
    $DefaultPageCancelButton.Add_Click({$ToolSelectionPageForm.Size = $ToolPageForm.Size; $ToolSelectionPageForm.Location = $ToolPageForm.Location; $ToolSelectionPageForm.Show()}) 
    $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
    [int]$FontSize = $SquareRootOfFormSize/35
    [int]$Margin = $SquareRootOfFormSize/20
    [int]$Padding = $SquareRootOfFormSize/125
    $ToolButtonPanel = New-Object Windows.Forms.FlowLayoutPanel -Property @{BackColor = "WhiteSmoke"; AutoScroll = $true;Anchor = "Top, Bottom, Left, Right"; Width = $ToolSelectionPageForm.Width - 16; Height = $ToolSelectionPageForm.Height - 82}
    $ToolButtonPanel.Add_SizeChanged(
    {
        $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
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
    $ExportExistingRulesToPowerShellCommandsButton.Add_Click({$ToolSelectionPageForm.Hide(); . ExportExistingRulesToPowerShellCommandsPage})
    $ExportExistingRulesToPowerShellCommandsToolTip = New-Object System.Windows.Forms.ToolTip
    $ExportExistingRulesToPowerShellCommandsToolTip.SetToolTip($ExportExistingRulesToPowerShellCommandsButton, "Use this tool to query a domain for policies`nthat have existing firewall rules and then`nexport a policy to a PowerShell script.`n100% complete.")
    $FindAllPoliciesWithFirewallRulesButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $FindAllPoliciesWithFirewallRulesButton.Text = "Find all policies with firewall rules"
    $FindAllPoliciesWithFirewallRulesButton.Add_Click({$ToolSelectionPageForm.Hide(); . FindAllPoliciesWithFirewallRulesPage})
    $FindAllPoliciesWithFirewallRulesToolTip = New-Object System.Windows.Forms.ToolTip
    $FindAllPoliciesWithFirewallRulesToolTip.SetToolTip($FindAllPoliciesWithFirewallRulesButton, "Use this tool to query a domain for policies`nthat have existing firewall rules, this list`ncan then be saved to a text file as reference.`n100% complete.")
    $UpdateDomainResourcesButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $UpdateDomainResourcesButton.Text = "  Update domain resources"
    $UpdateDomainResourcesButton.Add_Click({. UpdateDomainResourcesPage})
    $UpdateDomainResourcesToolTip = New-Object System.Windows.Forms.ToolTip -Property @{AutoPopDelay = 7500}
    $UpdateDomainResourcesToolTip.SetToolTip($UpdateDomainResourcesButton, "Use this tool to update domain resources that can be used`nto create or update firewall rules in group policy objects.`nNames can be used and will be translated into IP addresses`nwhich can be applied to multiple rules.`n25% complete.")
    $EditExistingFirewallRulesButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $EditExistingFirewallRulesButton.Text = "Edit existing firewall rules"
    $EditExistingFirewallRulesButton.Add_Click({$ToolSelectionPageForm.Hide(); . EditExistingFirewallRulesPage})
    $EditExistingFirewallRulesToolTip = New-Object System.Windows.Forms.ToolTip -Property @{AutoPopDelay = 7500}
    $EditExistingFirewallRulesToolTip.SetToolTip($EditExistingFirewallRulesButton, "Use this tool to edit existing firewall rules, domain resources can be`nselected and DNS will be used to resolve all IP addresses to be used.`nMultiple rules can be edited at once and saved to a PowerShell`nscript or saved back to the domain.`n50% complete.")
    $ScanComputerForBlockedConnectionsButton = New-Object Windows.Forms.Button -Property @{Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin; Size = $ExportExistingRulesToPowerShellCommandsButton.Size; BackColor = "DarkSlateGray"; ForeColor = "White"; Font = $BoldButtonFont}
    $ScanComputerForBlockedConnectionsButton.Text = "Scan computer for blocked connections"
    $ScanComputerForBlockedConnectionsButton.Add_Click({$ToolSelectionPageForm.Hide(); . ScanComputerForBlockedConnectionsPage})
    $ScanComputerForBlockedConnectionsToolTip = New-Object System.Windows.Forms.ToolTip
    $ScanComputerForBlockedConnectionsToolTip.SetToolTip($ScanComputerForBlockedConnectionsButton, "Use this tool to scan a computer for blocked network`nconnections and to create new firewall rules that can be`nsaved to a PowerShell script or saved to a group policy object.`n60% complete.")
    $ToolSelectionPageStatusBar = New-Object Windows.Forms.StatusBar -Property @{Dock = "Bottom"; Text = "Please select a tool to launch."}
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
