<#
.DESCRIPTION
    A set of Windows Firewall tools to create PowerShell firewall commands or to import/export rules to/from group policy objects. It contains blocked connection scanning and
    navigation between Windows Forms via a back button (BackButton). 
.NOTES
    ExportExistingRulesToPowerShellCommands
        If a policy is created from the output of this script and that policy is linked to the same OU as the source policy the link order will determine which rule is applied.
        Because the GUID is copied from the source they are not unique across policies, under normal conditions both rules with the same display name would be applied but
        because they conflict the policy higher in the link order will have it's rule applied and that will overwrite the lower policy rule.
    Build 1809.1
#>

if ((Get-Host).Name -eq "ServerRemoteHost" -or $PSVersionTable.PSEdition -eq "Core")
{
    PopUpMessage -Message "This script invokes a GUI and cannot be run over a remot session or on PowerShell Core editions)"
    break
}

Add-Type -Assembly "System.Windows.Forms"
[System.Windows.Forms.Application]::EnableVisualStyles()

class WindowsFirewallRule
{
    [string] $PolicyStore
    [string] $Name
    [string] $DisplayName
    [string] $Description
    [string] $Group 
    [ValidateSet("True","False")]
    [String] $Enabled
    [ValidateSet("Any","Domain","Private","Public")]
    [System.collections.arraylist] $Profile
    [ValidateSet("Inbound", "Outbound")]
    [string] $Direction
    [ValidateSet("Allow", "Block")]
    [string] $Action
    [System.collections.arraylist] $LocalAddress
    [System.collections.arraylist] $RemoteAddress
    [string] $Protocol
    [System.collections.arraylist] $LocalPort
    [System.collections.arraylist] $RemotePort
    [string] $Program
    [string] $Package
    [string] $Service
    [Object] Clone()
    {
        $ClonedObject = $this.MemberwiseClone()
        foreach ($Name in ($this| Get-Member).Where({$_.Definition -like "System.Collections.*"}).Name)
        {# Clone (deep copy) objects within an object
            $ClonedObject.$Name = $this.$Name.Clone()
        }
        return $ClonedObject
    }
}
    
function DefaultDomainResources
{
    [System.Collections.ArrayList]$Script:Resources = "DomainControllers","ProxyServers","DnsServers","CrlServers","Wpad_PacFileServers","TierXManagementServers","SqlServers","WebServers","FileServers","KeyManagementServers","BackupServers","ClusteredNodesAndManagementAddresses","ExternalVpnEndpoints","DirectAccessServers","TrustedDhcpSubnets","ServerRoleAdministrationServers"| Sort-Object
    foreach ($Resource in $Resources)
    {
        New-Variable -Name $Resource -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope "Script"
    }
    New-Variable -Name "ProxyServerPorts" -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope "Script"
    # Version 0.7.0 domain resources
    [System.Collections.ArrayList]$Script:DomainControllers += "127.0.0.1","SERVERNAME"
    [System.Collections.ArrayList]$Script:ProxyServerPorts += "8080"
    [System.Collections.ArrayList]$Script:ProxyServers += "LocalSubnet","Intranet"
    [System.Collections.ArrayList]$Script:DnsServers += $Script:DomainControllers # Specify these if you do not have DNS on each domain controller or you have additional DNS servers
    [System.Collections.ArrayList]$Script:CrlServers += "LocalSubnet","Intranet"
    [System.Collections.ArrayList]$Script:Wpad_PacFileServers += "LocalSubnet","Intranet"
    [System.Collections.ArrayList]$Script:TierXManagementServers += "LocalSubnet","Intranet" # These are used in tier X firewall baselines to define which computers can manage the device at a particular tier
    [System.Collections.ArrayList]$Script:SqlServers += "127.0.0.4"
    [System.Collections.ArrayList]$Script:WebServers += "LocalSubnet","Intranet"
    [System.Collections.ArrayList]$Script:FileServers += "LocalSubnet","Intranet"
    [System.Collections.ArrayList]$Script:KeyManagementServers += "LocalSubnet","Intranet"
    [System.Collections.ArrayList]$Script:BackupServers += "127.0.0.1"
    [System.Collections.ArrayList]$Script:ClusteredNodesAndManagementAddresses += "LocalSubnet","Intranet"
    [System.Collections.ArrayList]$Script:ExternalVpnEndpoints += "127.0.0.2 -  127.0.0.3" # This is the externally resolvable IPSec hostname or address
    [System.Collections.ArrayList]$Script:DirectAccessServers += "127.0.0.128/25" # This is the externally resolvable hostname or address of the DirectAccess IPHTTPS endpoint
    [System.Collections.ArrayList]$Script:TrustedDhcpSubnets += "Any" # This is client enterprise subnets and includes subnets issued by the VPN server, "Predefined set of computers" cannot be used here
    # END of version 0.7.0 domain resources
    # Version 0.8.0 domain resources
    [System.Collections.ArrayList]$Script:ServerRoleAdministrationServers += "LocalSubnet","Intranet" # These are trusted machines used by tier administrators permitted to administer a server role
    # END of version 0.8.0 domain resources
    [System.Collections.ObjectModel.ObservableCollection[Object]]$Script:ResourcesAndProxyPorts = $Resources + "ProxyServerPorts"| Sort-Object
}

function GroupPoliciesWithExistingFirewallRules
{
    $GroupPolicyObjects = (Get-GPO -All).DisplayName
    foreach ($GroupPolicyObject in $GroupPolicyObjects)
    {
        $GroupPolicyObjectIndex ++
        if (Get-NetFirewallRule -PolicyStore "$DomainName\$GroupPolicyObject" -ErrorAction SilentlyContinue)
        {
            $ProgressBar.Value = ($GroupPolicyObjectIndex * ($OneHundredPercent/$GroupPolicyObjects.Count))
            $StatusBar.Text = "Scanning policy $GroupPolicyObject"
            [string[]]$Script:GroupPoliciesWithExistingFirewallRules += $GroupPolicyObject
        }
    }
    Remove-Variable -Name "GroupPolicyObjectIndex" -Force
    $Script:GroupPoliciesWithExistingFirewallRules = $Script:GroupPoliciesWithExistingFirewallRules| Sort-Object
}

function GetComputerFileSystemVariables
{
    $DriveLetters = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
        (Get-WmiObject "Win32_Volume").DriveLetter
    }
    $ProgramFiles = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
        $env:ProgramFiles
    }
    $ProgramFilesX86 = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
        ${env:ProgramFiles(x86)}
    }
    $SystemRoot = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
        $env:SystemRoot
    }
}

function PopUpMessage ($Message,$CurrentForm = $ToolPageForm) # Need to use `r`n for newline
{
    $ReviewAndSaveForm.Location
    $PopUpMessageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        Location = @{
            X = ($CurrentForm.Location.X + 25)
            Y = ($CurrentForm.Location.Y + 25)
        }
        StartPosition = "Manual"
        MinimumSize = @{
            Width = 150
            Height = 100
        }
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
        AutoScroll = $true
    }
    $PopUpMessageBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $PopUpMessageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $PopUpMessageAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "OK"
        Anchor = "Right"
    }
    $PopUpMessageAcceptButton.Add_Click(
    {
        $PopUpMessageForm.Close()
    })
    $PopUpMessageAcceptButton.Left = $PopUpMessageBottomButtonPanel.Width - $PopUpMessageAcceptButton.Width - 5
    $PopUpMessageForm.CancelButton = $PopUpMessageAcceptButton
    $PopUpMessageForm.AcceptButton = $PopUpMessageAcceptButton
    $PopUpMessageTextBox = New-Object -TypeName "Windows.Forms.TextBox" -Property @{
        Multiline = $true
        BackColor = "GhostWhite"
        ReadOnly = $true
        Text = $Message
        MinimumSize = @{
            Width = 141
            Height = 70
        }
        MaximumSize = @{
            Width = 500
            Height = 500
        }
    }
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
    $CancelAcceptForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        Location = @{
            X = ($ToolPageForm.Location.X + 25)
            Y = ($ToolPageForm.Location.Y + 25)
        }
        StartPosition = "Manual"
        MinimumSize = @{
            Width = 200
            Height = 100
        }
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
        KeyPreview = $true
    }
    $CancelAcceptForm.Add_Shown(
    {
        $CancelAcceptAcceptButton.Focus()
    })
    $CancelAcceptForm.Add_KeyPress(
    {
        if ($_.KeyChar -eq "y")
        {
            $CancelAcceptAcceptButton.PerformClick()
        }
        elseif ($_.KeyChar -eq "n")
        {
            $CancelAcceptCancelButton.PerformClick()
        }
    })
    $CancelAcceptBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $CancelAcceptForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $CancelAcceptCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = $CancelButtonText
        Anchor = "Right"
    }
    $CancelAcceptCancelButton.Left = $CancelAcceptBottomButtonPanel.Width - $CancelAcceptCancelButton.Width - 5
    $CancelAcceptAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = $AcceptButtonText
        Anchor = "Right"
        DialogResult = "OK"
    }
    $CancelAcceptAcceptButton.Left = $CancelAcceptCancelButton.Left - $CancelAcceptAcceptButton.Width - 5
    $CancelAcceptForm.CancelButton = $CancelAcceptCancelButton
    $CancelAcceptForm.AcceptButton = $CancelAcceptAcceptButton
    $CancelAcceptTextBox = New-Object -TypeName "Windows.Forms.TextBox" -Property @{
        Multiline = $true
        BackColor = "GhostWhite"
        ReadOnly = $true
        Text = $Message
        MinimumSize = @{
            Width = 191
            Height = 70}
        }
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

function AttemptResolveDnsName ($Name)
{
    try
    {
        return (Resolve-DnsName $Name -ErrorAction Stop).IPAddress
    }
    catch
    {
        PopUpMessage -Message "The hostname`r`n$Name`r`ncould not be resolved,check connectivity`r`nto the DNS infrastructure and ensure`r`nthere is a valid host record for`r`n$Name."
    }
}

function SelectAll ($Control)
{
    if ($_.KeyData -eq "A, Control")
    {
        $_.SuppressKeyPress = $true
        $Control.BeginUpdate()
        for ($i = 0; $i -lt $Control.Items.Count; $i++)
        {
            $Control.SetSelected($i, $true)
        }
        $Control.EndUpdate()
    }
}

function ResetDataSource ($ResetDataSourceData)
{
    $ResetDataSourceDataSource = $ResetDataSourceData.DataSource
    $ResetDataSourceData.DataSource = $null
    $ResetDataSourceData.DataSource = $ResetDataSourceDataSource
    if ($ResetDataSourceData.Value)
    {
        $ResetDataSourceData.Value = $ResetDataSourceData.DataSource| Select-Object -Last 1
    }
    if ($ResetDataSourceData.DropDownWidth)
    {
        $ResetDataSourceData.DropDownWidth = (($ResetDataSourceData.DataSource).Length| Sort-Object -Descending| Select-Object -First 1) * 7
    }
}

function AddResource ($AddResourceProperty,$AddResourceValues)
{
    function AnyResource
    {
            foreach ($AddResourceValue in $AddResourceValues)
            {
                if ("Any" -in $AddResourceValue.Items)
                {
                    PopUpMessage -Message "`"Any`" is already in the list."
                }
                else
                {
                    if ((CancelAccept -Message "All other items in the list will be`r`nremoved, do you want to continue?" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "OK")
                    {
                        $AddResourceValue.DataSource.Clear()
                        $AddResourceTextBox.Text = "Any" # This will be used to set the value in the data source.
                        $AddResourceValue.DataSource.Add($AddResourceTextBox.Text)
                        ResetDataSource -ResetDataSourceData $AddResourceValue
                    }
                }
            }
        }
    if ($null -eq $DomainControllers)
    {
        DefaultDomainResources
    }
    $AddResourceForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        Location = @{
            X = ($ToolPageForm.Location.X + ($ToolPageForm.width/2)) - 140
            Y = ($ToolPageForm.Location.Y + ($ToolPageForm.Height/2)) - 70
        }
        StartPosition = "Manual"
        Width = 280
        Height = 140
        Text = "Add resource"
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
    }
    $AddResourceBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $AddResourceForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $AddResourceCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Exit"
        Anchor = "Right"
    } # This is not the default cancel button because the form size is different to the tool form?
    $AddResourceCancelButton.Left = $AddResourceBottomButtonPanel.Width - $AddResourceCancelButton.Width - 5
    $AddResourceAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Add"
        Anchor = "Right"
    } 
    $AddResourceAcceptButton.Left = $AddResourceCancelButton.Left - $AddResourceAcceptButton.Width - 5
    $AddResourcePanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $AddResourceForm.Width - 16
        Height = $AddResourceForm.Height - 82
    }
    $AddResourceTextBox = New-Object -TypeName "Windows.Forms.TextBox" -Property @{
        width = $AddResourcePanel.Width - 20
        Location = @{
            X = 10
            Y= 5
        }
    }
    $AddResourceLabel = New-Object -TypeName "Windows.Forms.Label" -Property @{
        TextAlign = "MiddleLeft"
        width = 80
        Height = 20
        Location = @{
            X = 10
            Y = $AddResourcePanel.Height - 28
        }
        Text= "Resource type:"
    }
    if ($AddResourceProperty -in "LocalPort","ProxyServerPorts","RemotePort")
    {
        $AddResourceAcceptButton.Add_Click(
        {
            if ($AddResourceComboBox1.SelectedItem -eq "Any")
            {
                AnyResource
            }
            else
            {
                function AddResourceValue
                {
                        foreach ($AddResourceValue in $AddResourceValues)
                        {
                            if ($TextBoxValue -in $AddResourceValue.Items)
                            {
                                PopUpMessage -Message "`"$($TextBoxValue)`" is already in the list."
                            }
                            else
                            {
                                $AddResourceValue.DataSource.Add($TextBoxValue)
                                ResetDataSource -ResetDataSourceData $AddResourceValue
                            }
                        }
                        foreach ($AddResourceValue in $AddResourceValues)
                        {
                            if ("Any" -in $AddResourceValue.Items -and $AddResourceValue.Items.Count -gt 1)
                            {
                                $AddResourceValue.DataSource.Remove("Any")
                                ResetDataSource -ResetDataSourceData $AddResourceValue
                            }
                        }
                    }
                try
                {
                    $TextBoxValue = $AddResourceTextBox.Text.replace(" ","")
                    if ($TextBoxValue -like "*-*" -and (($TextBoxValue).Split("-").Count -eq 2))
                    {
                        if (([int]($TextBoxValue).Split("-")[0] -in 1..65535) -and ([int]($TextBoxValue).Split("-")[1] -in 1..65535) -and ([int]($TextBoxValue).Split("-")[0] -lt [int]($TextBoxValue).Split("-")[1]))
                        {
                            AddResourceValue
                        }
                        else
                        {
                            PopUpMessage -Message "Invalid input."
                        }
                    }
                    elseif ([int]$TextBoxValue -in 1..65535)
                    {
                        AddResourceValue
                    }
                    else
                    {
                        PopUpMessage -Message "Invalid input."
                    }
                }
                catch
                {
                    PopUpMessage -Message "Invalid input."
                }
            }
        })
        $AddResourceComboBox1 = New-Object -TypeName "Windows.Forms.ComboBox" -Property @{
            width = 155
            Location = @{
                X = $AddResourcePanel.Width - 165
                Y = $AddResourcePanel.Height - 28
            }
            BackColor = "WhiteSmoke"
            DropDownStyle = "DropDownList"
        }
        $AddResourceComboBox1.DataSource = @("Port number","Any")
        $AddResourceComboBox1.Add_SelectedValueChanged(
        {
            switch ($AddResourceComboBox1.SelectedItem)
            {
                "Any"           {
                                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                                    $AddResourceStatusBar.Text = "Add `"Any IP address.`" "
                                    break
                                }
                "Port number"   {
                                    $AddResourceTextBox.Text = ""
                                    $AddResourcePanel.Controls.Add($AddResourceTextBox)
                                    $AddResourceStatusBar.Text = "Enter a port number or range from 1 to 65535."
                                    $AddResourceTextBox.Focus()
                                }
            }
        })
        $AddResourceStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Enter a port number or range from 1 to 65535."
        }
    }
    else
    {
        $AddResourceAcceptButton.Add_Click(
        {
            switch ($AddResourceComboBox1.SelectedItem)
                                                                                                                                                                                                                                                                                                                                                                                                                                                                        {
            "Any"                           {
                                                AnyResource
                                                break
                                            }
            "Predefined set of computers"   {
                                                foreach ($AddResourceValue in $AddResourceValues)
                                                {
                                                    if ($AddResourceComboBox2.SelectedValue -in $AddResourceValue.Items)
                                                    {
                                                        PopUpMessage -Message "`"$($AddResourceComboBox2.SelectedValue)`" is already in the list."
                                                    }
                                                    else
                                                    {
                                                        $AddResourceValue.DataSource.Add($AddResourceComboBox2.SelectedValue)
                                                        $AddResourceTextBox.Text = $AddResourceComboBox2.SelectedValue
                                                        ResetDataSource -ResetDataSourceData $AddResourceValue  
                                                    }
                                                }
                                                break
                                            }
            "Domain resource"               {
                                                foreach ($Value in (Get-Variable -Name $AddResourceComboBox2.SelectedValue).Value)
                                                {
                                                    foreach ($AddResourceValue in $AddResourceValues)
                                                    {
                                                        if ($Value -in $AddResourceValue.Items)
                                                        {
                                                            PopUpMessage -Message "`"$Value`" is already in the list."
                                                        }
                                                        else
                                                        {
                                                            $AddResourceValue.DataSource.Add($Value)
                                                        }
                                                        ResetDataSource -ResetDataSourceData $AddResourceValue
                                                    }  
                                                }
                                                break
                                            }
            "Computer name/IP address"      {
                                                foreach ($AddResourceValue in $AddResourceValues)
                                                {
                                                    $TextBoxValue = $AddResourceTextBox.Text.replace(" ","")
                                                    switch -Wildcard ($TextBoxValue)
                                                    {
                                                        "*/*"   { # A forward slash indicates a subnet has been specified, the subnet is not being validated in this build.
                                                                    if ($TextBoxValue -in $AddResourceValue.Items)
                                                                    {
                                                                        PopUpMessage -Message "$TextBoxValue is already in the list."
                                                                        break
                                                                    }
                                                                    else
                                                                    {
                                                                        $AddResourceValue.DataSource.Add($TextBoxValue)
                                                                        break
                                                                    }
                                                                }
                                                        "*-*"   {
                                                                    try
                                                                    { # If each side of the hyphen is an IP address then a range has been specified
                                                                        if ([ipaddress]$TextBoxValue.Split("-")[0] -and [ipaddress]$TextBoxValue.Split("-")[1])
                                                                        { 
                                                                            if ($TextBoxValue -in $AddResourceValue.Items)
                                                                            {
                                                                                PopUpMessage -Message "$TextBoxValue is already in the list."
                                                                                break
                                                                            }
                                                                            else
                                                                            {
                                                                                $AddResourceValue.DataSource.Add($TextBoxValue)
                                                                                break
                                                                            }
                                                                        }
                                                                    }
                                                                    catch [Management.Automation.PSInvalidCastException]
                                                                    {
                                                                        $IpAddresses = AttemptResolveDnsName -Name $TextBoxValue
                                                                    }
                                                                }
                                                        default {
                                                                    try
                                                                    {
                                                                        if ([ipaddress]$TextBoxValue)
                                                                        {
                                                                            $IpAddresses = $TextBoxValue
                                                                        }
                                                                    }
                                                                    catch [Management.Automation.PSInvalidCastException]
                                                                    {
                                                                        $IpAddresses = AttemptResolveDnsName -Name $TextBoxValue
                                                                    }
                                                                }
                                                    }
                                                    if ($IpAddresses)
                                                    {
                                                        foreach ($IpAddress in $IpAddresses)
                                                        {
                                                            if ($IpAddress -in $AddResourceValue.Items)
                                                            {
                                                                PopUpMessage -Message "$IpAddress is already in the list."
                                                            }
                                                            else
                                                            {
                                                                $AddResourceValue.DataSource.Add($IpAddress)
                                                            }
                                                        }
                                                    }
                                                    ResetDataSource -ResetDataSourceData $AddResourceValue
                                                }
                                            }
        }
            foreach ($AddResourceValue in $AddResourceValues)
            {
                if ("Any" -in $AddResourceValue.Items -and $AddResourceValue.Items.Count -gt 1)
                {
                    $AddResourceValue.DataSource.Remove("Any")
                    ResetDataSource -ResetDataSourceData $AddResourceValue
                }
            }
        })
        $AddResourceComboBox1 = New-Object -TypeName "Windows.Forms.ComboBox" -Property @{
            width = 155
            Location = @{
                X = $AddResourcePanel.Width - 165
                Y = $AddResourcePanel.Height - 28
            }
            BackColor = "WhiteSmoke"
            DropDownStyle = "DropDownList"
        }
        $AddResourceComboBox1.DataSource = @("Computer name/IP address","Domain resource","Predefined set of computers","Any")
        $AddResourceComboBox1.Add_SelectedValueChanged(
        {
            switch ($AddResourceComboBox1.SelectedItem)
            {
                "Any"                           {
                                                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                                                    $AddResourcePanel.Controls.Remove($AddResourceComboBox2)
                                                    $AddResourceStatusBar.Text = "Add `"Any IP address.`" "
                                                    break
                                                }
                "Predefined set of computers"   {
                                                    $AddResourceComboBox2.DataSource = "DefaultGateway","DHCP","DNS","Internet","Intranet","LocalSubnet"
                                                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                                                    $AddResourcePanel.Controls.Add($AddResourceComboBox2)
                                                    $AddResourceStatusBar.Text = "Select a predefined set of computers to add."
                                                    $AddResourceTextBox.Focus()
                                                    break
                                                }
                "Domain resource"               {
                                                    $AddResourceComboBox2.DataSource = $Resources
                                                    $AddResourcePanel.Controls.Remove($AddResourceTextBox)
                                                    $AddResourcePanel.Controls.Add($AddResourceComboBox2)
                                                    $AddResourceStatusBar.Text = "Select an existing domain resource to add."
                                                    $AddResourceComboBox2.Focus()
                                                    break
                                                }
                "Computer name/IP address"      {
                                                    $AddResourceTextBox.Text = ""
                                                    $AddResourcePanel.Controls.Remove($AddResourceComboBox2)
                                                    $AddResourcePanel.Controls.Add($AddResourceTextBox)
                                                    $AddResourceStatusBar.Text = "Enter a computer name or IP address to add."
                                                    $AddResourceTextBox.Focus()
                                                }
            }
        })
        $AddResourceComboBox2 = New-Object -TypeName "Windows.Forms.ComboBox" -Property @{
            width = $AddResourcePanel.Width - 20
            Location = @{
                X = 10
                Y= 5
            }
            DropDownStyle = "DropDownList"
        }
        $AddResourceStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Enter a computer name or IP address to add."
        }
    }
    $AddResourceForm.CancelButton = $AddResourceCancelButton
    $AddResourceForm.AcceptButton = $AddResourceAcceptButton
    $AddResourceBottomButtonPanel.Controls.Add($AddResourceCancelButton)
    $AddResourceBottomButtonPanel.Controls.Add($AddResourceAcceptButton)
    $AddResourcePanel.Controls.Add($AddResourceTextBox)
    $AddResourcePanel.Controls.Add($AddResourceLabel)
    $AddResourcePanel.Controls.Add($AddResourceComboBox1)
    $AddResourceForm.Controls.Add($AddResourcePanel) # Added to the form first to set focus on this panel
    $AddResourceForm.Controls.Add($AddResourceBottomButtonPanel)
    $AddResourceForm.Controls.Add($AddResourceStatusBar)
    [void]$AddResourceForm.ShowDialog()
}

function RemoveResource ($RemoveResourceProperty,$RemoveResourceDataObjects,$RemoveResourceSelectedItems)
{
    foreach ($RemoveResourceDataObject in $RemoveResourceDataObjects)
    {
        foreach ($RemoveResourceSelectedItem in $RemoveResourceSelectedItems)
        {
            $RemoveResourceDataObject.DataSource.Remove($RemoveResourceSelectedItem)
        }
        if ($RemoveResourceDataObject.DataSource.Count -eq 0)
        {
            $RemoveResourceDataObject.DataSource.Add("Any")
        }
        ResetDataSource -ResetDataSourceData $RemoveResourceDataObject
    }
}

function ChangeValue ($ChangeValueProperty,$ChangeValueDataObjects)
{
    if ($ChangeValueProperty -in "Enabled", "Direction","Action")
    {
        switch ($ChangeValueProperty)
        {
            "Enabled"   {# 1 value (True/False)
                            $Value1 = $true
                            $Value2 = $false
                        }
            "Direction" {# 1 value (Inbound/Outbound)
                            $Value1 = "Inbound"
                            $Value2 = "Outbound"
                        }
            "Action"    {# 1 value (Allow/Block)
                            $Value1 = "Allow"
                            $Value2 = "Block"
                        }
        }
        foreach ($ChangeValueDataObject in $ChangeValueDataObjects)
        {
            if ($ChangeValueDataObject.Value -eq $Value1)
            {
                $ChangeValueDataObject.Value = $Value2    
            }
            else
            {
                $ChangeValueDataObject.Value = $Value1
            }
        }
    }
    elseif ($ChangeValueProperty -in  "Group","Profile","Protocol","Program","Package","Service")
    {
        PopUpMessage -Message "Not available in this build."
    }
    else
    {
        $ChangeValueForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
            FormBorderStyle = "FixedDialog"
            KeyPreview = $true
            Location = @{
                X = ($ToolPageForm.Location.X + ($ToolPageForm.width/2)) - 125
                Y = ($ToolPageForm.Location.Y + ($ToolPageForm.Height/2)) - 55
            }
            StartPosition = "Manual"
            Width = 250
            Height = 110
            Text = "Change value"
            MaximizeBox = $false
            MinimizeBox = $false
            ControlBox = $false
        }
        $ChangeValueBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
            Width = $ChangeValueForm.Width - 16
            Height = 22
            Dock = "Bottom"
            BackColor = "WhiteSmoke"
        }
        $ChangeValueCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
            Text = "Exit"
            Anchor = "Right"
        }# This is not the default cancel button because the form size is different to the tool form?
        $ChangeValueCancelButton.Left = $ChangeValueBottomButtonPanel.Width - $ChangeValueCancelButton.Width - 5
        $ChangeValueAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
            Text = "Change"
            Anchor = "Right"
        }
        $ChangeValueAcceptButton.Left = $ChangeValueCancelButton.Left - $ChangeValueAcceptButton.Width - 5
        $ChangeValueAcceptButton.Add_Click(
        {
            function ChangeDataObject
            {
                foreach ($ChangeValueDataObject in $ChangeValueDataObjects)
                {
                    $ChangeValueDataObject.Value = $ChangeValueTextBox.Text
                }
                $ChangeValueForm.Close()
            }
            switch ($ChangeValueProperty)
            {
                "DisplayName"   {# 1 value
                                    if ($ChangeValueTextBox.Text -eq "")
                                    {
                                        PopUpMessage -Message "DisplayName needs a value."
                                    }
                                    else
                                    {
                                        ChangeDataObject
                                    }
                                    break
                                }
                "Description"   {# 1 value or blank
                                    ChangeDataObject
                                    break
                                }
                "Group"         {# 1 value or blank
                                    break
                                }
                "Profile"       {# 1 value, 2 values or any
                                    break
                                }
                "Protocol"      {# Only supporting TCP and UDP in this build
                                    break
                                }
                "Program"       {# 1 value or any
                                    break
                                }
                "Package"       {# 1 value, any package or any
                                    break
                                }
                "Service"       {# 1 value, any service or any
                                    break
                                }
            }
        })
        $ChangeValueForm.CancelButton = $ChangeValueCancelButton
        $ChangeValueForm.AcceptButton = $ChangeValueAcceptButton
        $ChangeValueTextBox = New-Object -TypeName "Windows.Forms.TextBox" -Property @{
            width = $ChangeValueForm.Width - 36
            Location = @{
                X = 10
                Y= 5
            }
        }
        if ($ChangeValueProperty -in "DisplayName","Description" -and $ChangeValueDataObjects.Count -eq 1)
        {
            $ChangeValueTextBox.Text = $ChangeValueDataObjects.Value
        }
        $ChangeValueStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Enter a new value for $ChangeValueProperty."
        }
        $ChangeValuePanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
            AutoScroll = $true
            Anchor = "Top, Bottom, Left, Right"
            Width = $ChangeValueForm.Width - 16
            Height = $ChangeValueForm.Height - 82
        }
        if ($ChangeValueProperty -in "DisplayName","Description")
        {
            $ChangeValuePanel.Controls.Add($ChangeValueTextBox)
        }
        $ChangeValueBottomButtonPanel.Controls.Add($ChangeValueCancelButton)
        $ChangeValueBottomButtonPanel.Controls.Add($ChangeValueAcceptButton)
        $ChangeValueForm.Controls.Add($ChangeValuePanel) # Added to the form first to set focus on this panel
        $ChangeValueForm.Controls.Add($ChangeValueBottomButtonPanel)
        $ChangeValueForm.Controls.Add($ChangeValueStatusBar)
        [void]$ChangeValueForm.ShowDialog()
    }
}

function BuildCommands ([ValidateSet("True", "False")]$ExistingRules = $false)
{
    function ReviewAndSave
    {
        $ReviewAndSaveForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
            FormBorderStyle = "Sizable"
            Location = @{
                x = $ToolPageForm.Location.X + 25
                Y = $ToolPageForm.Location.Y + 25
            }
            StartPosition = "Manual"
            Size = $ToolPageForm.Size
            MinimumSize = $ToolPageForm.MinimumSize
            WindowState = $ToolPageForm.WindowState
            Text = "Review and save"
        }
        $ReviewAndSaveBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
            Width = $ReviewAndSaveForm.Width - 16
            Height = 22
            Dock = "Bottom"
            BackColor = "WhiteSmoke"
        }
        $ReviewAndSaveCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
            Text = "Exit"
            Anchor = "Right"
        }
        $ReviewAndSaveCancelButton.Left = $ReviewAndSaveBottomButtonPanel.Width - $ReviewAndSaveCancelButton.Width - 16
        $ReviewAndSaveSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
        $ReviewAndSaveSaveFileDialog.Filter = "PowerShell Files (*.ps1)|*.ps1|All files (*.*)|*.*"
        $ReviewAndSaveSaveAsButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
            Text = "Save As"
            Anchor = "Right"
        }
        $ReviewAndSaveSaveAsButton.Add_Click(
        {
            if ($ReviewAndSaveSaveFileDialog.ShowDialog() -eq "OK")
            {
                $ReviewAndSaveCommandsListBox.Items| Out-File -FilePath $ReviewAndSaveSaveFileDialog.FileName
            }
        })
        $ReviewAndSaveSaveAsButton.Left = $ReviewAndSaveCancelButton.Left - $ReviewAndSaveSaveAsButton.Width - 5 
        $ReviewAndSaveSaveToGpoButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
            Text = "Save to GPO"
            Anchor = "Right"
            Width = 80
        }
        $ReviewAndSaveSaveToGpoButton.Add_Click(
        {
            try
            {
                $ReviewAndSaveStatusBar.Text = "Updating domain group policy object."
                foreach ($Command in $Commands)
                {
                    Invoke-Expression -Command $Command
                }
                PopUpMessage -Message "Domain group policy object updated." -CurrentForm $ReviewAndSaveForm
            }
            catch
            {
                PopUpMessage -Message $error[0] -CurrentForm = $ReviewAndSaveForm
            }
            $ReviewAndSaveStatusBar.Text = "Review the commands and save them to a .ps1 or back to the domain GPO."
        })
        $ReviewAndSaveSaveToGpoButton.Left = $ReviewAndSaveSaveAsButton.Left - $ReviewAndSaveSaveToGpoButton.Width - 5 
        $ReviewAndSaveForm.CancelButton = $ReviewAndSaveCancelButton
        $ReviewAndSaveCommandsListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
            DataSource = $Commands
            Dock = "Fill"
            HorizontalScrollbar = $true
            SelectionMode = "None"
        }
        $ReviewAndSaveStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
            Dock = "Bottom"
            Text = "Review the commands and save them to a .ps1 or back to the domain GPO."
        }
        $ReviewAndSavePanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
            Anchor = "Top, Bottom, Left, Right"
            AutoScroll = $true
            Width = $ReviewAndSaveForm.Width - 16
            Height = $ReviewAndSaveForm.Height - 82
        }
        $ReviewAndSaveBottomButtonPanel.Controls.Add($ReviewAndSaveCancelButton)
        $ReviewAndSaveBottomButtonPanel.Controls.Add($ReviewAndSaveSaveAsButton)
        $ReviewAndSaveBottomButtonPanel.Controls.Add($ReviewAndSaveSaveToGpoButton)
        $ReviewAndSavePanel.Controls.Add($ReviewAndSaveCommandsListBox)
        $ReviewAndSaveForm.Controls.Add($ReviewAndSavePanel) # Added to the form first to set focus on this panel
        $ReviewAndSaveForm.Controls.Add($ReviewAndSaveBottomButtonPanel)
        $ReviewAndSaveForm.Controls.Add($ReviewAndSaveStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
        [void]$ReviewAndSaveForm.ShowDialog()
    }
    if ($ExistingRules)
    {
        $ChangesFound = $false
        $Cmdlet = "Set-NetFirewallRule"
        $Commands = New-Object -TypeName "System.Collections.ArrayList"
        $Commands.Add("`$GpoSession = Open-NetGPO -PolicyStore `"$(($WindowsFirewallRules[0].PolicyStore -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$'))`"")
        foreach ($SelectedIndex in $SelectedIndices)
        {
            $NewLine = $true
            foreach ($PropertyName in ($WindowsFirewallRules[0].PsObject.Properties).name)
            {
                if (Compare-Object -ReferenceObject $WindowsFirewallRulesClone[$SelectedIndex] -DifferenceObject $WindowsFirewallRules[$SelectedIndex] -Property $PropertyName)
                {
                    if ($NewLine)
                    {
                        $ChangesFound = $true
                        $NewLine = $false
                        $EscapedName = ($WindowsFirewallRulesClone[$SelectedIndex].Name -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
                        $Index = $Commands.Add("Set-NetFirewallRule -GPOSession `$GpoSession -Name `"$EscapedName`"")
                    }
                    $EscapedValue = (($WindowsFirewallRules[$SelectedIndex].$PropertyName -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$') -join '","')
                    $Commands[$Index] = $Commands[$Index] + " -" + $PropertyName.Replace("DisplayName","NewDisplayName") + (" `"$EscapedValue`"")
                }
            }
        }
        if (-not $ChangesFound)
        {
            PopUpMessage -Message "No changes were found in the selected rules."
        }
        else
        {
            $Commands.Add("Save-NetGPO -GPOSession `$GpoSession")
            ReviewAndSave
        }
    }
    else
    {
        $Cmdlet = "New-NetFirewallRule"
    }
}

function EditFirewallRules # This is designed to be called from inside a click event, the object will be placed in the scope of the calling function.
{
    New-Variable -Name "EditFirewallRulesDataGridViewPanel" -Value (New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Dock = "Fill"
        BackColor = "WhiteSmoke"
    }) -Scope 2 -Force
    $EditFirewallRulesDataGridViewPanel.Add_SizeChanged(
    {
        $EditFirewallRulesDataGridViewButtonPanel.MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = 22
        }
        $EditFirewallRulesDataGridView.MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = $ToolPageForm.Height - 120
        }
    })
    New-Variable -Name "EditFirewallRulesDataGridView" -Value (New-Object -TypeName "System.Windows.Forms.DataGridView" -Property @{
        AutoSize = $true
        SelectionMode = "CellSelect"
        BackGroundColor = "WhiteSmoke"
        Dock = "None"
        AutoGenerateColumns = $false
        ColumnHeadersHeightSizeMode = "AutoSize"
        MaximumSize = @{
            Width = $ToolPageForm.Width - 16
            Height = $ToolPageForm.Height - 120
        }
        RowHeadersVisible = $false
    }) -Scope 2 -Force
    $EditFirewallRulesDataGridView.Add_SizeChanged(
    {
        $EditFirewallRulesDataGridView.Size = $EditFirewallRulesDataGridView.PreferredSize
        $EditFirewallRulesDataGridViewButtonPanel.Location = @{
            X = 0
            Y = $EditFirewallRulesDataGridView.Bottom
        }
        $EditFirewallRulesDataGridViewButtonPanel.Width = $EditFirewallRulesDataGridView.width
        $EditFirewallRulesDataGridViewAddButton.Left = $EditFirewallRulesDataGridViewRemoveButton.Left - $EditFirewallRulesDataGridViewAddButton.Width - 5
    })
    $EditFirewallRulesDataGridView.Add_CurrentCellChanged(
    {
        if ($EditFirewallRulesDataGridView.CurrentCell.DropDownWidth)
        {
            $EditFirewallRulesDataGridView.CurrentCell.DropDownWidth = (($EditFirewallRulesDataGridView.CurrentCell.DataSource).Length| Sort-Object -Descending| Select-Object -First 1) * 7
        }
        if ($EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -eq 0)
        {
            $EditFirewallRulesDataGridViewRemoveButton.Visible = $false
            $EditFirewallRulesDataGridViewAddButton.Visible = $false
            $EditFirewallRulesDataGridViewChangeButton.Visible = $false
        }
        elseif ($EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -in "LocalAddress","RemoteAddress","LocalPort","RemotePort")
        {
            $EditFirewallRulesDataGridViewRemoveButton.Visible = $true
            $EditFirewallRulesDataGridViewAddButton.Visible = $true
            $EditFirewallRulesDataGridViewChangeButton.Visible = $false
        }
        else
        {
            $EditFirewallRulesDataGridViewRemoveButton.Visible = $false
            $EditFirewallRulesDataGridViewAddButton.Visible = $false
            $EditFirewallRulesDataGridViewChangeButton.Visible = $true
        }
        if ($EditFirewallRulesDataGridView.SelectedCells.Count -lt 2)
        {
            Set-Variable -Name "SelectedColumnIndex" -Value $EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -Scope 1
        }
        elseif ($EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -ne (Get-Variable -Name "SelectedColumnIndex" -Scope 1).Value)
        {
            $EditFirewallRulesDataGridView.ClearSelection()
            $EditFirewallRulesDataGridView.CurrentCell.Selected = $true
            Set-Variable -Name "SelectedColumnIndex" -Value $EditFirewallRulesDataGridView.CurrentCell.ColumnIndex -Scope 1
        }
    })
    New-Variable -Name "SelectedColumnIndex" -Value 0 -Scope 2 -Force
    $EditFirewallRulesDataGridView.Columns.Insert(0, (New-Object -TypeName "System.Windows.Forms.DataGridViewCheckBoxColumn"))
    $EditFirewallRulesDataGridView.Columns[0].AutoSizeMode = "AllCellsExceptHeader"
    $EditFirewallRulesDataGridView.Columns[0].Frozen = $true
    $ColumnIndex = 1
    $EmptyWindowsFirewallRule = New-Object -TypeName "WindowsFirewallRule"
    foreach ($PropertyName in ($EmptyWindowsFirewallRule.PsObject.Properties).name)
    {
        if ($PropertyName -ne "PolicyStore" -and $PropertyName -ne "Name")
        {
            if ($PropertyName -in "DisplayName","Description","Group","Enabled","Direction","Action","Protocol","Program","Package","Service")
            {
                $EditFirewallRulesDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewTextBoxColumn" -Property @{
                    ReadOnly = $true
                }))
                $EditFirewallRulesDataGridView.Columns[$ColumnIndex].Name = $PropertyName
                $EditFirewallRulesDataGridView.Columns["$PropertyName"].DataPropertyName = $PropertyName
            }
            else
            {
                $EditFirewallRulesDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewComboBoxColumn" -Property @{
                    FlatStyle = "Popup"
                }))
                $EditFirewallRulesDataGridView.Columns[$ColumnIndex].Name = $PropertyName
            }
            $ColumnIndex ++
        }
    }
    $EditFirewallRulesDataGridView.Columns[1].Frozen = $true
    $EditFirewallRulesDataGridView.Columns[1].Width = 150
    New-Variable -Name "EditFirewallRulesDataGridViewButtonPanel" -Value (New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $EditFirewallRulesDataGridView.Width
        Height = 22
        Dock = "None"
        BackColor = "WhiteSmoke"
        Location = @{
            X = 0
            Y = $EditFirewallRulesDataGridView.Bottom
        }
    }) -Scope 2 -Force
    New-Variable -Name "EditFirewallRulesDataGridViewRemoveButton" -Value (New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Remove"
        Anchor = "Right"
    }) -Scope 2 -Force
    $EditFirewallRulesDataGridViewRemoveButton.Left = $EditFirewallRulesDataGridViewButtonPanel.Width - $EditFirewallRulesDataGridViewRemoveButton.Width - 16
    $EditFirewallRulesDataGridViewRemoveButton.Add_Click(
    {# Most of this should move to the RemoveResource function with a test to see if the selected cell is a ComboBox.
        $SelectItemsToRemoveListBox = New-Object -TypeName "Windows.Forms.ListBox" -Property @{
            AutoSize = $true
            BackColor = "GhostWhite"
            Dock = "Fill"
            SelectionMode = "MultiExtended"
            }
        foreach ($SelectedCell in $EditFirewallRulesDataGridView.SelectedCells)
        {
            foreach ($Item in $SelectedCell.Items)
            {
                if ($Item -notin $SelectItemsToRemoveListBox.Items -and $Item -ne "Any")
                {
                    $SelectItemsToRemoveListBox.Items.ADD($Item)
                }
            }
        }
        if ($SelectItemsToRemoveListBox.Items.Count)
        { 
            $SelectItemsToRemoveForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
                AutoSize = $true
                FormBorderStyle = "FixedDialog"
                StartPosition = "Manual"
                MinimumSize = @{
                    Width = 200
                    Height = 100
                }
            }
            $SelectItemsToRemoveForm.Add_Shown(
            {
                $SelectItemsToRemoveForm.Focus()
                $SelectItemsToRemoveForm.Location = @{
                    X = ($EditFirewallRulesDataGridViewPanel.Location.X + $EditFirewallRulesDataGridViewPanel.Width / 2)
                    Y = ($EditFirewallRulesDataGridViewPanel.Location.Y + $EditFirewallRulesDataGridViewPanel.Height / 2)
                }

            })
            $SelectItemsToRemoveBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
                Width = $SelectItemsToRemoveForm.Width - 16
                Height = 22
                Dock = "Bottom"
                BackColor = "WhiteSmoke"
            }
             $SelectItemsToRemoveCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
                Text = "Exit"
                Anchor = "Right"
            }
            $SelectItemsToRemoveCancelButton.Left = $SelectItemsToRemoveBottomButtonPanel.Width - $SelectItemsToRemoveCancelButton.Width - 5
            $SelectItemsToRemoveAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
                Text = "Remove"
                Anchor = "Right"
                DialogResult = "OK"
            }
            $SelectItemsToRemoveAcceptButton.Left = $SelectItemsToRemoveCancelButton.Left - $SelectItemsToRemoveAcceptButton.Width - 5
            $SelectItemsToRemoveForm.CancelButton = $SelectItemsToRemoveCancelButton
            $SelectItemsToRemoveForm.AcceptButton = $SelectItemsToRemoveAcceptButton
            $SelectItemsToRemoveStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
                Dock = "Bottom"
                Text = "Please select one or more resource to remove."
            }
            $SelectItemsToRemoveListBox.Size = $SelectItemsToRemoveListBox.PreferredSize
            $SelectItemsToRemoveBottomButtonPanel.Controls.Add($SelectItemsToRemoveCancelButton)
            $SelectItemsToRemoveBottomButtonPanel.Controls.Add($SelectItemsToRemoveAcceptButton)
            $SelectItemsToRemoveForm.Controls.Add($SelectItemsToRemoveListBox)
            $SelectItemsToRemoveForm.Controls.Add($SelectItemsToRemoveBottomButtonPanel)
            $SelectItemsToRemoveForm.Controls.Add($SelectItemsToRemoveStatusBar)
            if ($SelectItemsToRemoveForm.ShowDialog() -eq "OK")
            {
                RemoveResource -RemoveResourceProperty $EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -RemoveResourceDataObjects $EditFirewallRulesDataGridView.SelectedCells -RemoveResourceSelectedItems $SelectItemsToRemoveListBox.SelectedItems
            }
        }
        else
        {
            PopUpMessage -Message "No resources were found that can be removed."
        }
    })
    New-Variable -Name "EditFirewallRulesDataGridViewAddButton" -Value (New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Add"
        Anchor = "Right"
    }) -Scope 2 -Force
    $EditFirewallRulesDataGridViewAddButton.Left = $EditFirewallRulesDataGridViewRemoveButton.Left - $EditFirewallRulesDataGridViewAddButton.Width - 5
    $EditFirewallRulesDataGridViewAddButton.Add_Click(
    {
        AddResource -AddResourceProperty $EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -AddResourceValues $EditFirewallRulesDataGridView.SelectedCells
    })
    New-Variable -Name "EditFirewallRulesDataGridViewChangeButton" -Value (New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Change"
        Anchor = "Right"
        Visible = $false
    }) -Scope 2 -Force
    $EditFirewallRulesDataGridViewChangeButton.Left = $EditFirewallRulesDataGridViewButtonPanel.Width - $EditFirewallRulesDataGridViewChangeButton.Width - 16
    $EditFirewallRulesDataGridViewChangeButton.Add_Click(
    {
        ChangeValue -ChangeValueProperty $EditFirewallRulesDataGridView.CurrentCell.OwningColumn.Name -ChangeValueDataObjects $EditFirewallRulesDataGridView.SelectedCells
    })
    $EditFirewallRulesDataGridViewButtonPanel.Controls.Add($EditFirewallRulesDataGridViewRemoveButton)
    $EditFirewallRulesDataGridViewButtonPanel.Controls.Add($EditFirewallRulesDataGridViewChangeButton)
    $EditFirewallRulesDataGridViewButtonPanel.Controls.Add($EditFirewallRulesDataGridViewAddButton)
    $EditFirewallRulesDataGridViewPanel.Controls.Add($EditFirewallRulesDataGridView)
    $EditFirewallRulesDataGridViewPanel.Controls.Add($EditFirewallRulesDataGridViewButtonPanel)
}

function FindAllPoliciesWithFirewallRulesPage
{
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Find all policies with firewall rules"
    } 
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                Anchor = "Left"
            }
            $FindAllPoliciesWithFirewallRulesBottomButtonPanel.Controls.Add($ProgressBar)
            $FindAllPoliciesWithFirewallRulesGpoListBox.Hide()
            $StatusBar = $FindAllPoliciesWithFirewallRulesStatusBar
            GroupPoliciesWithExistingFirewallRules
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
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $FindAllPoliciesWithFirewallRulesBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $FindAllPoliciesWithFirewallRulesSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
    $FindAllPoliciesWithFirewallRulesSaveFileDialog.Filter = "Text Files (*.txt)|*.txt|All files (*.*)|*.*"
    $FindAllPoliciesWithFirewallRulesSaveAsButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Save As"
        Anchor = "Right"
    }
    $FindAllPoliciesWithFirewallRulesSaveAsButton.Add_Click(
    {
        if ($FindAllPoliciesWithFirewallRulesSaveFileDialog.ShowDialog() -eq "OK")
        {
            $FindAllPoliciesWithFirewallRulesGpoListBox.Items| Out-File -FilePath $FindAllPoliciesWithFirewallRulesSaveFileDialog.FileName
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $FindAllPoliciesWithFirewallRulesGpoListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
        SelectionMode = "None"
    }
    $FindAllPoliciesWithFirewallRulesStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Scanning policies."
    }
    $FindAllPoliciesWithFirewallRulesPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
    $FindAllPoliciesWithFirewallRulesPanel.Controls.Add($FindAllPoliciesWithFirewallRulesGpoListBox)
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesBottomButtonPanel)
    $ToolPageForm.Controls.Add($FindAllPoliciesWithFirewallRulesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function UpdateDomainResourcesPage
{
    if ($null -eq $DomainControllers)
    {
        DefaultDomainResources
    }
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Update domain resources"
    }
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $UpdateDomainResourcesBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $DefaultPageCancelButton.Left = $UpdateDomainResourcesBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
    $UpdateDomainResourcesSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
    $UpdateDomainResourcesSaveFileDialog.Filter = "XML Files (*.xml)|*.xml|All files (*.*)|*.*"
    $UpdateDomainResourcesExportButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Export"
        Anchor = "Right"
    }
    $UpdateDomainResourcesExportButton.Left = $DefaultPageCancelButton.Left - $UpdateDomainResourcesExportButton.Width - 5
    $UpdateDomainResourcesExportButton.Add_Click(
    {
        if ($UpdateDomainResourcesSaveFileDialog.ShowDialog() -eq "OK")
        {
            $ResourcesArray = @()
            foreach ($Resource in $ResourcesAndProxyPorts)
            {
                $ResourcesArray += Get-Variable -Name $Resource -Scope "Script"

            }
            Export-Clixml -InputObject $ResourcesArray -Path $UpdateDomainResourcesSaveFileDialog.FileName -Force
        }
    })
    $UpdateDomainResourcesOpenFileDialog =  New-Object -TypeName "System.Windows.Forms.OpenFileDialog"
    $UpdateDomainResourcesOpenFileDialog.Filter = "XML Files (*.xml)|*.xml|All files (*.*)|*.*"
    $UpdateDomainResourcesImportButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Import"
        Anchor = "Right"
    }
    $UpdateDomainResourcesImportButton.Left = $UpdateDomainResourcesExportButton.Left - $UpdateDomainResourcesImportButton.Width - 5
    $UpdateDomainResourcesImportButton.Add_Click(
    {
        if ($UpdateDomainResourcesOpenFileDialog.ShowDialog() -eq "OK")
        {
            $ResourcesArray = Import-Clixml -Path $UpdateDomainResourcesOpenFileDialog.FileName
            foreach ($Resource in $ResourcesArray)
            {
                New-Variable -Name $Resource.Name -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope "Script" -Force
                Set-Variable -Name $Resource.Name -Value $Resource.Value -Scope "Script"
            }
            $UpdateDomainResourcesResourcesListBox.SetSelected(0, $true)
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $UpdateDomainResourcesResourcesListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        Anchor = "Top,Left"
        Location = @{
            X = 13
            Y = 13
        }
        BorderStyle = "Fixed3D"
        Size = @{
            Width = 212
            Height = 250
        }
    }
    $UpdateDomainResourcesResourcesListBox.Add_SelectedValueChanged(
    {
        $UpdateDomainResourcesValuesListBox.DataSource = (Get-Variable -Name $UpdateDomainResourcesResourcesListBox.SelectedItem).Value
    })
    $UpdateDomainResourcesResourcesListBox.DataSource = $Script:ResourcesAndProxyPorts
    $UpdateDomainResourcesValuesContextMenuStrip = New-Object -TypeName "System.Windows.Forms.ContextMenuStrip"
    $UpdateDomainResourcesValuesContextMenuStrip.Items.Add("Remove")
    $UpdateDomainResourcesValuesContextMenuStrip.Add_ItemClicked(
    {
        $UpdateDomainResourcesRemoveButton.PerformClick()
    })
    $UpdateDomainResourcesValuesListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        Anchor = "Top,Left,Right"
        Location = @{
            X = ($UpdateDomainResourcesResourcesListBox.Location.X + $UpdateDomainResourcesResourcesListBox.Width + 13)
            Y = 13
        }
        BorderStyle = "Fixed3D"
        Size = @{
            Width = ($ToolPageForm.Width - 269)
            Height = $UpdateDomainResourcesResourcesListBox.Height - 35
        }
        SelectionMode = "MultiExtended"
        ContextMenuStrip = $UpdateDomainResourcesValuesContextMenuStrip
    }
    $UpdateDomainResourcesValuesListBox.Add_KeyDown(
    {
        SelectAll -Control $UpdateDomainResourcesValuesListBox
    })
    $UpdateDomainResourcesRemoveButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Remove"
        Anchor = "Top,Right"
        Location = @{
            X = $ToolPageForm.Width - $UpdateDomainResourcesRemoveButton.Width - 105
            Y = $UpdateDomainResourcesValuesListBox.Location.Y + $UpdateDomainResourcesValuesListBox.Height + 5
        }
    }
    $UpdateDomainResourcesRemoveButton.Add_Click(
    {
        RemoveResource -RemoveResourceProperty $UpdateDomainResourcesResourcesListBox.SelectedItem -RemoveResourceDataObjects $UpdateDomainResourcesValuesListBox -RemoveResourceSelectedItems $UpdateDomainResourcesValuesListBox.SelectedItems
    })
    $UpdateDomainResourcesAddButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Add"
        Anchor = "Top,Right"
        Location = @{
            Y = $UpdateDomainResourcesRemoveButton.Location.Y
        }
    }
    $UpdateDomainResourcesAddButton.Left = $UpdateDomainResourcesRemoveButton.Left - $UpdateDomainResourcesAddButton.Width - 5
    $UpdateDomainResourcesAddButton.Add_Click(
    {
        AddResource -AddResourceProperty $UpdateDomainResourcesResourcesListBox.SelectedValue -AddResourceValues $UpdateDomainResourcesValuesListBox
    })
    $UpdateDomainResourcesStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Please select a resource to update."
    }
    $UpdateDomainResourcesPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
    $UpdateDomainResourcesBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
    $UpdateDomainResourcesBottomButtonPanel.Controls.Add($UpdateDomainResourcesExportButton)
    $UpdateDomainResourcesBottomButtonPanel.Controls.Add($UpdateDomainResourcesImportButton)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesResourcesListBox)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesValuesListBox)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesRemoveButton)
    $UpdateDomainResourcesPanel.Controls.Add($UpdateDomainResourcesAddButton)
    $ToolPageForm.Controls.Add($UpdateDomainResourcesPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($UpdateDomainResourcesBottomButtonPanel)
    $ToolPageForm.Controls.Add($UpdateDomainResourcesStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function EditExistingFirewallRulesPage
{   
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        KeyPreview = $true
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Edit existing firewall rules"
    }
    $ToolPageForm.Add_Closing(
    {
        if ($EditFirewallRulesDataGridViewPanel.Parent)
        {
            if ((CancelAccept -Message "Are you sure, any unsaved`r`nchanges will be lost?" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "Cancel")
            {
                $_.Cancel = $true
            }
        }
    })
    $ToolPageForm.Add_KeyUp(
    {
        if ($_.KeyCode -eq "Back" -and -not $EditExistingFirewallRulesGpoListBox.Parent)
        {
            $EditExistingFirewallRulesBackButton.PerformClick()
        }
    })
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            if ((CancelAccept -Message "Do you want to search for group policies`r`nwith existing firewall rules or select`r`nfrom a list of all group policies?" -CancelButtonText "Search" -AcceptButtonText "Select") -eq "CANCEL")
            {
                $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                    Anchor = "Left"
                }
                $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($ProgressBar)
                $EditExistingFirewallRulesGpoListBox.Hide()
                $StatusBar = $EditExistingFirewallRulesStatusBar
                GroupPoliciesWithExistingFirewallRules
                $EditExistingFirewallRulesBottomButtonPanel.Controls.Remove($ProgressBar)
                $EditExistingFirewallRulesGroupPolicies = $Script:GroupPoliciesWithExistingFirewallRules
            }
            else
            {
                $EditExistingFirewallRulesGroupPolicies = (Get-GPO -All).DisplayName| Sort-Object
            }
        }
        else
        {
            $EditExistingFirewallRulesGroupPolicies = $Script:GroupPoliciesWithExistingFirewallRules
        }
        foreach ($EditExistingFirewallRules in $EditExistingFirewallRulesGroupPolicies)
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
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $EditExistingFirewallRulesBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $EditExistingFirewallRulesAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Select"
        Anchor = "Right"
    }
    $EditExistingFirewallRulesAcceptButtonClick =
    {# This is created as a script outside the click event because it's also used as a double click event, if the double click event calls the click event that would create an additional scope and object data is lost
        if ($EditExistingFirewallRulesGpoListBox.Parent)
        {
            $EditExistingFirewallRulesStatusBar.Text = "Building rule collection."
            $EditExistingFirewallRulesRulesListBox.Items.Clear()
            $GpoSession = Open-NetGPO -PolicyStore "$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)"
            New-Variable -Name "EditExistingFirewallRulesRulesArray" -Value @() -Scope 1 -Force
            if (Get-NetFirewallRule -GPOSession $GpoSession| Select-Object -First 1)
            {
                foreach ($EditExistingFirewallRulesRule in (Get-NetFirewallRule -GPOSession $GpoSession| Sort-Object -Property "DisplayName"))
                {
                    Set-Variable -Name "EditExistingFirewallRulesRulesArray" -Value ((Get-Variable "EditExistingFirewallRulesRulesArray").Value + $EditExistingFirewallRulesRule.Name) -Scope 1
                    $EditExistingFirewallRulesRulesListBox.Items.Add($EditExistingFirewallRulesRule.DisplayName)
                }
                $EditExistingFirewallRulesStatusBar.Text = "Please select one or more rules to display."
                $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
                $EditExistingFirewallRulesBottomButtonPanel.Controls.Add($EditExistingFirewallRulesBackButton)
                $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesGpoListBox)
                $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
                $EditExistingFirewallRulesRulesListBox.SetSelected(0, $true)
                $EditExistingFirewallRulesRulesListBox.Focus()
            }
            else
            {
                PopUpMessage -Message "$($EditExistingFirewallRulesGpoListBox.SelectedItem)`r`ndoes not contain any firewall rules."
                $EditExistingFirewallRulesStatusBar.Text = "Please select a GPO to display."
            }
            Remove-Variable -Name "GpoSession" -Force
        }
        elseif ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            if (($EditExistingFirewallRulesRulesListBox.SelectedIndices).Count -ne 0)
            {
            $GpoSession = Open-NetGPO -PolicyStore ("$DomainName\$($EditExistingFirewallRulesGpoListBox.SelectedItem)")
            New-Variable -Name "WindowsFirewallRules" -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope 1 -Force
            New-Variable -Name "WindowsFirewallRulesClone" -Value (New-Object -TypeName "System.Collections.ArrayList") -Scope 1 -Force
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
                    Profile = @(($EditExistingFirewallRulesRule.Profile).Tostring().Replace(",","").Split())
                    Direction = $EditExistingFirewallRulesRule.Direction
                    Action = $EditExistingFirewallRulesRule.Action
                    LocalAddress = @(($EditExistingFirewallRulesRule| Get-NetFirewallAddressFilter -GPOSession $GpoSession).LocalAddress)
                    RemoteAddress = @(($EditExistingFirewallRulesRule| Get-NetFirewallAddressFilter -GPOSession $GpoSession).RemoteAddress)
                    Protocol = ($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).Protocol
                    LocalPort = @((($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).LocalPort).Replace("RPC","135"))
                    RemotePort = @((($EditExistingFirewallRulesRule| Get-NetFirewallPortFilter -GPOSession $GpoSession).RemotePort).Replace("RPC","135").Replace("IPHTTPS","443"))
                    Program = ($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Program
                    Package = ($EditExistingFirewallRulesRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package
                    Service = ($EditExistingFirewallRulesRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service
                }
                Set-Variable -Name "WindowsFirewallRules" -Value ([System.Collections.ArrayList]((Get-Variable -Name "WindowsFirewallRules").value + $WindowsFirewallRule)) -Scope 1
                Set-Variable -Name "WindowsFirewallRulesClone" -Value ([System.Collections.ArrayList]((Get-Variable -Name "WindowsFirewallRulesClone").value + $WindowsFirewallRule.Clone())) -Scope 1
            }
            Remove-Variable -Name "GpoSession" -Force
            $EditExistingFirewallRulesStatusBar.Text = "$($WindowsFirewallRules.Count) rule(s) imported, edit rules and then select one or more rules to create the commands."
            EditFirewallRules
            $EditFirewallRulesDataGridView.DataSource = $WindowsFirewallRules
            $EditExistingFirewallRulesAcceptButton.Text = "Create"
            $EditExistingFirewallRulesPanel.Controls.Add($EditFirewallRulesDataGridViewPanel)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRulesListBox)
            UpdateDataSourceForComboBoxCell -ArrayList $WindowsFirewallRules -DataGridView $EditFirewallRulesDataGridView # This needs to run after the gridview control has been added so that the rows exist
            }
            else
            {
                PopUpMessage -Message "Please select one or more rules to edit."
            }
        }
        elseif ($EditFirewallRulesDataGridViewPanel.Parent)
        {
            [int[]]$SelectedIndices = @()
            for ($i = 0; $i -lt $EditFirewallRulesDataGridView.Rows.Count; $i++)
            {
                if ($($EditFirewallRulesDataGridView.Rows[$i].Cells[0].Value) -eq $true)
                {
                    $SelectedIndices += $i
                }
            }
            if ($SelectedIndices.Count)
            {
                BuildCommands -ExistingRules $true
            }
            else
            {
                PopUpMessage -Message "Please select one or more rules."
            }
        }
    }
    $EditExistingFirewallRulesAcceptButton.Add_Click($EditExistingFirewallRulesAcceptButtonClick)
    $EditExistingFirewallRulesBackButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Back"
        Anchor = "Right"
    }
    $EditExistingFirewallRulesBackButton.Left = $EditExistingFirewallRulesAcceptButton.Left - $EditExistingFirewallRulesBackButton.Width - 5
    $EditExistingFirewallRulesBackButton.Add_Click(
    {
        if ($EditExistingFirewallRulesRulesListBox.Parent)
        {
            $EditExistingFirewallRulesStatusBar.Text = "Please select a GPO to display."
            $EditExistingFirewallRulesBottomButtonPanel.Controls.Remove($EditExistingFirewallRulesBackButton)
            $EditExistingFirewallRulesPanel.Controls.Remove($EditExistingFirewallRulesRulesListBox)
            $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesGpoListBox)
            $EditExistingFirewallRulesGpoListBox.Focus()
        }
        elseif ($EditFirewallRulesDataGridView.Parent)
        {
            if ((CancelAccept -Message "Are you sure, any unsaved`r`nchanges will be lost?" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "OK")
            {
                $EditExistingFirewallRulesStatusBar.Text = "$($WindowsFirewallRules.Count) rule(s) imported, select one or more rules to edit."
                $EditExistingFirewallRulesAcceptButton.Text = "Select"
                $EditExistingFirewallRulesPanel.Controls.Remove($EditFirewallRulesDataGridViewPanel)
                $EditExistingFirewallRulesPanel.Controls.Add($EditExistingFirewallRulesRulesListBox)
                $EditExistingFirewallRulesRulesListBox.Focus()
            }
        }
    })
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ToolPageForm.AcceptButton = $EditExistingFirewallRulesAcceptButton
    $EditExistingFirewallRulesGpoListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
    }
    $EditExistingFirewallRulesGpoListBox.Add_DoubleClick($EditExistingFirewallRulesAcceptButtonClick)
    $EditExistingFirewallRulesRulesListBox = New-Object "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
        SelectionMode = "MultiExtended"
    }
    $EditExistingFirewallRulesRulesListBox.Add_DoubleClick($EditExistingFirewallRulesAcceptButtonClick)
    $EditExistingFirewallRulesRulesListBox.Add_KeyDown(
    {
        SelectAll -Control $EditExistingFirewallRulesRulesListBox
    })
    $EditExistingFirewallRulesStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
    }
    $EditExistingFirewallRulesPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
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
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "FixedDialog"
        KeyPreview = $true
        Location = @{
            X = ($ToolSelectionPageForm.Location.X + ($ToolSelectionPageForm.width/2)) - 125
            Y = ($ToolSelectionPageForm.Location.Y + ($ToolSelectionPageForm.Height/2)) - 55
        }
        StartPosition = "Manual"
        Width = 250
        Height = 110
        Text = "Scan computer for blocked connections"
        MaximizeBox = $false
        MinimizeBox = $false
        ControlBox = $false
    }
    $ToolPageForm.Add_Closing(
    {
        if ($EditFirewallRulesDataGridViewPanel.Parent)
        {
            if ((CancelAccept -Message "Are you sure, any unsaved`r`nchanges will be lost?" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "Cancel")
            {
                $_.Cancel = $true
            }
        }
    })
    $ToolPageForm.Add_KeyUp(
    {
        if ($_.KeyCode -eq "Back" -and -not $ScanComputerForBlockedConnectionsTextBox.Parent)
        {
            $ScanComputerForBlockedConnectionsBackButton.PerformClick()
        }
    })
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $ScanComputerForBlockedConnectionsBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $ScanComputerForBlockedConnectionsCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Exit"
        Anchor = "Right"
    }
    $ScanComputerForBlockedConnectionsCancelButton.Left = $ScanComputerForBlockedConnectionsBottomButtonPanel.Width - $ScanComputerForBlockedConnectionsCancelButton.Width - 5
    $ScanComputerForBlockedConnectionsCancelButton.Add_Click(
    {
        $ToolSelectionPageForm.Show()
    }) # This is not the default cancel button because the form size is different to the tool form?
    $ScanComputerForBlockedConnectionsAcceptButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Scan"
        Anchor = "Right"
    }
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
                    [ipaddress[]]$IpAddresses = AttemptResolveDnsName $Computer
                    if ($null -eq $IpAddresses)
                    {
                        throw "DNS name does not exist"
                    }
                }
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
                $ScanComputerForBlockedConnectionsStatusBar.Text = "Trying $(($NetworkConnectivityJobs).Count) IP address(es)."
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
                            if ((CancelAccept -Message "All network connectivity jobs have failed,`r`ndo you want to display diagnostic information?" -CancelButtonText "No" -AcceptButtonText "Yes") -eq "OK")
                            {
                                foreach ($NetworkConnectivityJob in $NetworkConnectivityJobs)
                                {
                                    [array]$DiagnosticResults += $NetworkConnectivityJob.Value.Exception.InnerException
                                }
                                PopUpMessage -Message $DiagnosticResults
                                throw "Connectivity test failed."   
                            }
                        }
                        if ((Get-Date) -gt $WaitTime)
                        {
                            if ((CancelAccept -Message "Network connectivity tests are taking longer than expected,`r`nthis function requires TCP ports 135,5985 and 49152-65535.`r`nDo you want to continue?" -CancelButtonText "Abort" -AcceptButtonText "Continue") -eq "Cancel")
                            {
                                throw "Connectivity test aborted, scanning cancelled."
                            }
                            $WaitTime = (Get-Date).AddSeconds(10)
                        }
                        Start-Sleep -Milliseconds 500
                    }
                }
                Until ($NetworkConnectivityJobRanToCompletion -eq $true)
                [datetime]$NetworkStateChange =  (Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                    LogName = "Microsoft-Windows-NetworkProfile/Operational"
                    ID = 4004
                } -MaxEvents 1 -ErrorAction Stop).TimeCreated.AddSeconds("1")
                if ((Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"}))
                {
                    if ((CancelAccept -Message "A $((Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"}).State) job has been found for this computer.`r`nDo you wants to connect to that job or start a new scan?" -CancelButtonText "New" -AcceptButtonText "Connect") -eq "Cancel")
                    {
                        (Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"})| Remove-Job
                        $EventsJob = Invoke-Command -ComputerName $Computer -ScriptBlock {
                            $Events = (Get-WinEvent -FilterHashtable @{
                                LogName = "Security"
                                ID = 5157
                                StartTime = $args[0]
                            } -MaxEvents 500 -ErrorAction Stop)
                            $Events
                        } -AsJob -ArgumentList $NetworkStateChange
                    }
                    else
                    {
                        $EventsJob = (Get-Job).Where({$_.Location -eq $Computer -and $_.Command -like "*Get-WinEvent*"})
                    }
                }
                else
                {
                    $EventsJob = Invoke-Command -ComputerName $Computer -ScriptBlock {
                        $Events = (Get-WinEvent -FilterHashtable @{
                            LogName = "Security"
                            ID = 5157
                            StartTime = $args[0]
                        } -MaxEvents 500 -ErrorAction Stop)
                        $Events
                    } -AsJob -ArgumentList $NetworkStateChange
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
                        if ((CancelAccept -Message "$Computer`r`nscanning is taking longer than expected. If you`r`nabort waiting for this scan to complete the scan`r`nwill continue in the background and you can`r`ntry to get the results by starting a scan on`r`n$Computer`r`nDo you want to continue?" -CancelButtonText "Abort" -AcceptButtonText "Continue") -eq "Cancel")
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
                $RunningServices = Get-CimInstance -CimSession $ComputerCimSession -Class "Win32_Service" -Filter "State = 'Running'"
                $ComputerCimSession| Remove-CimSession
                $ComputerPsSession = New-PSSession -ComputerName $Computer
                . GetComputerFileSystemVariables 
                [array]$AdHarvest = Invoke-Command -Session $ComputerPsSession -ScriptBlock {
                    (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc\Parameters\ADHarvest\" -Name "LastFetchContents").LastFetchContents.Split(",")
                } # Not currently used
                $ComputerPsSession| Remove-PSSession
                [NetworkConnection[]]$InboundNetworkConnections = @()
                [NetworkConnection[]]$OutboundNetworkConnections = @()
                $EventCount = 1
                $EventTotal = ($Events.Message).Count
                foreach ($Event in $Events.Message) # This sometimes stops interacting with the desktop but the processing contunues and the grid view is eventually shown.
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
                $ToolPageForm.Location = $ToolSelectionPageForm.Location # Need to look closer at this.
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
                UpdateDataSourceForComboBoxCell -ArrayList $NetworkConnections -DataGridView $ScanComputerForBlockedConnectionsDataGridView
            }
            catch [System.Management.Automation.RuntimeException]
            {
                if ($error[0].Exception.Message -in "Connectivity test aborted, scanning cancelled.","Waiting for scan job to complete aborted.","DNS name does not exist")
                {
                }
                elseif ($error[0].Exception.Message -eq "Connectivity test failed.")
                {
                    PopUpMessage -Message "Connectivity test failed, is`r`n$Computer`r`navalable on the network and are`r`nTCP ports 135,5985 and 49152-65535`r`nopen from this computer."
                }
                elseif ($error[0].Exception.Message -eq "No events were found that match the specified selection criteria.")
                {
                    PopUpMessage -Message "No matching events were found since the last network`r`nstate change on $(($NetworkStateChange.AddSeconds(-1)).ToString()), event ID 4004 in`r`nlog 'Microsoft-Windows-NetworkProfile/Operational'"
                }
                else
                {
                    PopUpMessage -Message "Scan failed.`r`n$($error[0].Exception.Message)System.Management.Automation.RuntimeException"
                }
            }
            catch
            {
                PopUpMessage -Message "Scan failed.`r`n$($error[0].Exception.Message)"
            }
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
        }
        elseif ($ScanComputerForBlockedConnectionsDataGridView.Parent)
        {
             PopUpMessage -Message "Not available in this build."
             # Build firewall rules from selected and call EditFireWallRules
        }
    })
    $ScanComputerForBlockedConnectionsBackButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Back"
        Anchor = "Right"
    }
    $ScanComputerForBlockedConnectionsBackButton.Left = $ScanComputerForBlockedConnectionsAcceptButton.Left - $ScanComputerForBlockedConnectionsBackButton.Width - 5
    $ScanComputerForBlockedConnectionsBackButton.Add_Click(
    {
        if ($ScanComputerForBlockedConnectionsDataGridView.Parent)
        {
            $ScanComputerForBlockedConnectionsBottomButtonPanel.Controls.Remove($ScanComputerForBlockedConnectionsBackButton)
            $ScanComputerForBlockedConnectionsPanel.Controls.Remove($ScanComputerForBlockedConnectionsDataGridView)
            $ToolPageForm.FormBorderStyle = "FixedDialog"
            $ToolPageForm.Location = @{
                X = ($ToolSelectionPageForm.Location.X + ($ToolSelectionPageForm.width/2)) - 125
                Y = ($ToolSelectionPageForm.Location.Y + ($ToolSelectionPageForm.Height/2)) - 55
            }
            $ToolPageForm.MinimumSize = @{
                Width = 0
                Height = 0
            }
            $ToolPageForm.Size = @{
                Width = 250
                Height = 110
            }
            $ToolPageForm.WindowState = "Normal"
            $ToolPageForm.MaximizeBox = $false
            $ToolPageForm.MinimizeBox = $false
            $ToolPageForm.ControlBox = $false
            $ScanComputerForBlockedConnectionsAcceptButton.Text = "Scan"
            $ScanComputerForBlockedConnectionsStatusBar.Text = "Enter a computer name or IP address to scan."
            $ScanComputerForBlockedConnectionsPanel.Controls.Add($ScanComputerForBlockedConnectionsTextBox)
            $ScanComputerForBlockedConnectionsTextBox.focus()
        }
    })
    $ToolPageForm.CancelButton = $ScanComputerForBlockedConnectionsCancelButton
    $ToolPageForm.AcceptButton = $ScanComputerForBlockedConnectionsAcceptButton
    $ScanComputerForBlockedConnectionsDataGridView = New-Object -TypeName "System.Windows.Forms.DataGridView" -Property @{
        AutoSize = $true
        BackGroundColor = "WhiteSmoke"
        Dock = "Fill"
        AutoGenerateColumns = $false
        ColumnHeadersHeightSizeMode = 'AutoSize'
        RowHeadersVisible = $false
    }
    $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert(0, (New-Object -TypeName "System.Windows.Forms.DataGridViewCheckBoxColumn"))
    $ScanComputerForBlockedConnectionsDataGridView.Columns[0].AutoSizeMode = "AllCellsExceptHeader"
    $ColumnIndex = 1
    $EmptyNetworkConnection = New-Object -TypeName "NetworkConnection"
    foreach ($PropertyName in ($EmptyNetworkConnection.PsObject.Properties).name)
    {
        if ($PropertyName -in "ProcessId","Application","Direction","SourceAddress","SourcePort","DestAddress","DestPort","Protocol","Notes")
        {
            $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewTextBoxColumn" -Property @{
                ReadOnly = $true
            }))
            $ScanComputerForBlockedConnectionsDataGridView.Columns[$ColumnIndex].Name = $PropertyName
            $ScanComputerForBlockedConnectionsDataGridView.Columns["$PropertyName"].DataPropertyName = $PropertyName
            $ColumnIndex ++
        }
        else
        {
            $ScanComputerForBlockedConnectionsDataGridView.Columns.Insert($ColumnIndex, (New-Object -TypeName "System.Windows.Forms.DataGridViewComboBoxColumn" -Property @{
                FlatStyle = "Popup"
            }))
            $ScanComputerForBlockedConnectionsDataGridView.Columns[$ColumnIndex].Name = $PropertyName
            $ColumnIndex ++
        }
    }
    $ScanComputerForBlockedConnectionsTextBox = New-Object -TypeName "Windows.Forms.TextBox" -Property @{
        width = $ToolPageForm.Width - 36
        Location = @{
            X = 10
            Y= 5
        }
        Text = "LocalHost"
    }
    $ScanComputerForBlockedConnectionsStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Enter a computer name or IP address to scan."
    }
    $ScanComputerForBlockedConnectionsPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
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
    $ToolPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        Location = $ToolSelectionPageForm.Location
        StartPosition = "Manual"
        Size = $ToolSelectionPageForm.Size
        MinimumSize = $ToolSelectionPageForm.MinimumSize
        WindowState = $ToolSelectionPageForm.WindowState
        Text = "Export existing rules to PowerShell commands"
    }
    $ToolPageForm.Add_Shown(
    {
        if ($null -eq $Script:GroupPoliciesWithExistingFirewallRules)
        {
            $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                Anchor = "Left"
            }
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ProgressBar)
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Hide()
            $StatusBar = $ExportExistingRulesToPowerShellCommandsStatusBar
            GroupPoliciesWithExistingFirewallRules
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
        }
        foreach ($ExportExistingRulesToPowerShellCommands in $Script:GroupPoliciesWithExistingFirewallRules)
        { # Loop through GPOs and add to listbox 
            [void]$ExportExistingRulesToPowerShellCommandsGpoListBox.Items.Add($ExportExistingRulesToPowerShellCommands)
        }
        $DefaultPageCancelButton.Left = $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Width - $DefaultPageCancelButton.Width - 16
        $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a policy to export."
        $ExportExistingRulesToPowerShellCommandsSaveAsButton.Left = $DefaultPageCancelButton.Left - $ExportExistingRulesToPowerShellCommandsSaveAsButton.Width - 5 
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($DefaultPageCancelButton)
        $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsSaveAsButton)
        $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
    })
    $ToolPageForm.Add_SizeChanged(
    {
        $ToolSelectionPageForm.WindowState = $ToolPageForm.WindowState
    })
    $ExportExistingRulesToPowerShellCommandsBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $ToolPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog =  New-Object -TypeName "System.Windows.Forms.SaveFileDialog"
    $ExportExistingRulesToPowerShellCommandsSaveFileDialog.Filter = "PowerShell Files (*.ps1)|*.ps1|All files (*.*)|*.*"
    $ExportExistingRulesToPowerShellCommandsSaveAsButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Save As"
        Anchor = "Right"
    }
    $ExportExistingRulesToPowerShellCommandsSaveAsButtonClick =
    {# This is created as a script outside the click event because it's also used as a double click event, if the double click event calls the click event that would create an additional scope and object data is lost
        if ($ExportExistingRulesToPowerShellCommandsSaveFileDialog.ShowDialog() -eq "OK")
        {
            $ProgressBar = New-Object -TypeName "System.Windows.Forms.ProgressBar" -Property @{
                Anchor = "Left"
            }
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Add($ProgressBar)
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Hide()
            $GPOSession = Open-NetGPO -PolicyStore ("$DomainName\$($ExportExistingRulesToPowerShellCommandsGpoListBox.SelectedItem)")
            [array]$FirewallRules = Get-NetFirewallRule -GPOSession $GPOSession
            $RuleProgress = 1
            foreach ($FirewallRule in $FirewallRules)
            {
                $ProgressBar.Value = ($RuleProgress*($OneHundredPercent/$FirewallRules.Count))
                $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Exporting rule $($FirewallRule.DisplayName)" 
                $RuleProgress ++
                $Command = @"
New-NetFirewallRule -GPOSession `$GPOSession
"@
                $Value = ($FirewallRule.Name  -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
                $Command += @"
 -Name "$Value"
"@
                $Value = ($FirewallRule.DisplayName  -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
                $Command += @"
 -DisplayName "$Value"
"@
                $Value = ($FirewallRule.Description  -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
                if ($Value -ne $null)
                {
                    $Command += @"
 -Description "$Value"
"@
                }
                $Value = ($FirewallRule.Group  -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
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
                $Value = (($FirewallRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Program  -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
                if ($Value -ne "Any")
                {
                    $Command += @"
 -Program "$Value"
"@
                } 
                $Value = (($FirewallRule| Get-NetFirewallApplicationFilter -GPOSession $GPOSession).Package  -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
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
                $Value = (($FirewallRule| Get-NetFirewallServiceFilter -GPOSession $GPOSession).Service  -replace '`','``' -replace "'","``'" -replace '"','`"').Replace('$','`$')
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
            Remove-Variable -Name "GPOSession" -Force
            $ExportExistingRulesToPowerShellCommandsStatusBar.Text = "Select a policy to export."
            $ExportExistingRulesToPowerShellCommandsGpoListBox.Show()
            $ExportExistingRulesToPowerShellCommandsBottomButtonPanel.Controls.Remove($ProgressBar)
        }
    }
    $ExportExistingRulesToPowerShellCommandsSaveAsButton.Add_Click($ExportExistingRulesToPowerShellCommandsSaveAsButtonClick)
    $ToolPageForm.CancelButton = $DefaultPageCancelButton
    $ToolPageForm.AcceptButton = $ExportExistingRulesToPowerShellCommandsSaveAsButton
    $ExportExistingRulesToPowerShellCommandsGpoListBox = New-Object -TypeName "System.Windows.Forms.ListBox" -Property @{
        AutoSize = $true
        BackColor = "WhiteSmoke"
        Dock = "Fill"
    }
    $ExportExistingRulesToPowerShellCommandsGpoListBox.Add_DoubleClick($ExportExistingRulesToPowerShellCommandsSaveAsButtonClick)
    $ExportExistingRulesToPowerShellCommandsStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Select a policy to export."
    }
    $ExportExistingRulesToPowerShellCommandsPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolPageForm.Width - 16
        Height = $ToolPageForm.Height - 82
    }
    $ExportExistingRulesToPowerShellCommandsPanel.Controls.Add($ExportExistingRulesToPowerShellCommandsGpoListBox)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsPanel) # Added to the form first to set focus on this panel
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsBottomButtonPanel)
    $ToolPageForm.Controls.Add($ExportExistingRulesToPowerShellCommandsStatusBar) # Added to the form last to ensure the status bar gets put at the bottom
    [void]$ToolPageForm.ShowDialog()
}

function MainThread
{
    $DomainName = $env:USERDNSDOMAIN
    $OneHundredPercent = 100
    $FontSizeDivisor = 45
    $MarginDivisor = 20
    $PaddingDivisor = 125
    $ToolSelectionPageForm = New-Object -TypeName "Windows.Forms.Form" -Property @{
        FormBorderStyle = "Sizable"
        StartPosition = "CenterScreen"
        Width = 1024
        Height = 512
        MinimumSize = @{
            Width = 310
            Height = 200
        }
        Text = "Windows firewall tool selection"
    }
    $ToolSelectionPageBottomButtonPanel = New-Object -TypeName "Windows.Forms.Panel" -Property @{
        Width = $ToolSelectionPageForm.Width - 16
        Height = 22
        Dock = "Bottom"
        BackColor = "WhiteSmoke"
    }
    $ToolSelectionPageCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Exit"
        Anchor = "Right"
    }
    $ToolSelectionPageCancelButton.Left = $ToolSelectionPageBottomButtonPanel.Width - $ToolSelectionPageCancelButton.Width - 16
    $ToolSelectionPageForm.CancelButton = $ToolSelectionPageCancelButton
    $DefaultPageCancelButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Text = "Exit"
        Anchor = "Right"
    }
    $DefaultPageCancelButton.Add_Click(
    {
        $ToolSelectionPageForm.Size = $ToolPageForm.Size
        $ToolSelectionPageForm.Location = $ToolPageForm.Location
    })
    $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
    [int]$FontSize = $SquareRootOfFormSize / $FontSizeDivisor
    [int]$Margin = $SquareRootOfFormSize / $MarginDivisor
    [int]$Padding = $SquareRootOfFormSize / $PaddingDivisor
    $ToolButtonPanel = New-Object -TypeName "Windows.Forms.FlowLayoutPanel" -Property @{
        BackColor = "WhiteSmoke"
        AutoScroll = $true
        Anchor = "Top, Bottom, Left, Right"
        Width = $ToolSelectionPageForm.Width - 16
        Height = $ToolSelectionPageForm.Height - 82
        FlowDirection = "LeftToRight"
    }
    $ToolButtonPanel.Add_SizeChanged(
    {
        $SquareRootOfFormSize = [math]::Sqrt($ToolSelectionPageForm.Width * $ToolSelectionPageForm.Height)
        [int]$FontSize = $SquareRootOfFormSize / $FontSizeDivisor
        [int]$Margin = $SquareRootOfFormSize / $MarginDivisor
        [int]$Padding = $SquareRootOfFormSize / $PaddingDivisor
        $BoldButtonFont = New-Object -TypeName "System.Drawing.Font"("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold)
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
    $BoldButtonFont = New-Object -TypeName "System.Drawing.Font"("Microsoft Sans Serif",($FontSize),[System.Drawing.FontStyle]::Bold) 
    $ExportExistingRulesToPowerShellCommandsButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Margin = $Margin
        Padding = $Padding
        Width = 270
        Height = 84
        AutoSize = $true
        AutoSizeMode = "GrowAndShrink"
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $ExportExistingRulesToPowerShellCommandsButton.Text = "Export existing`n rules to`nPowerShell commands" # As this button contains the most text all other buttons will inherit it's size
    $ExportExistingRulesToPowerShellCommandsButton.Add_SizeChanged(
    {
        $FindAllPoliciesWithFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $UpdateDomainResourcesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $EditExistingFirewallRulesButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
        $ScanComputerForBlockedConnectionsButton.Size = $ExportExistingRulesToPowerShellCommandsButton.Size
    })
    $ExportExistingRulesToPowerShellCommandsButton.Add_Click(
    {
        $ToolSelectionPageForm.Hide()
        ExportExistingRulesToPowerShellCommandsPage
        $ToolSelectionPageForm.Show()   
    })
    $ExportExistingRulesToPowerShellCommandsToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $ExportExistingRulesToPowerShellCommandsToolTip.SetToolTip($ExportExistingRulesToPowerShellCommandsButton, "Use this tool to query a domain for policies`nthat have existing firewall rules and then`nexport a policy to a PowerShell script.`n100% complete.")
    $FindAllPoliciesWithFirewallRulesButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $FindAllPoliciesWithFirewallRulesButton.Text = "Find all policies with firewall rules"
    $FindAllPoliciesWithFirewallRulesButton.Add_Click(
    {
        $ToolSelectionPageForm.Hide()
        FindAllPoliciesWithFirewallRulesPage
        $ToolSelectionPageForm.Show()   
    })
    $FindAllPoliciesWithFirewallRulesToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $FindAllPoliciesWithFirewallRulesToolTip.SetToolTip($FindAllPoliciesWithFirewallRulesButton, "Use this tool to query a domain for policies`nthat have existing firewall rules, this list`ncan then be saved to a text file as reference.`n100% complete.")
    $UpdateDomainResourcesButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $UpdateDomainResourcesButton.Text = "  Update domain resources"
    $UpdateDomainResourcesButton.Add_Click(
    {
        $ToolSelectionPageForm.Hide()
        UpdateDomainResourcesPage
        $ToolSelectionPageForm.Show()   
    })
    $UpdateDomainResourcesToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip" -Property @{
        AutoPopDelay = 7500
    }
    $UpdateDomainResourcesToolTip.SetToolTip($UpdateDomainResourcesButton, "Use this tool to update domain resources that can be used`nto create or update firewall rules in group policy objects.`nNames can be used and will be translated into IP addresses`nwhich can be applied to multiple rules.`n100% complete.")
    $EditExistingFirewallRulesButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $EditExistingFirewallRulesButton.Text = "Edit existing firewall rules"
    $EditExistingFirewallRulesButton.Add_Click(
    {
        $ToolSelectionPageForm.Hide()
        EditExistingFirewallRulesPage
        $ToolSelectionPageForm.Show()   
    })
    $EditExistingFirewallRulesToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip" -Property @{
        AutoPopDelay = 7500
    }
    $EditExistingFirewallRulesToolTip.SetToolTip($EditExistingFirewallRulesButton, "Use this tool to edit existing firewall rules, domain resources can be`nselected and DNS will be used to resolve all IP addresses to be used.`nMultiple rules can be edited at once and saved to a PowerShell`nscript or saved back to the domain.`n95% complete.")
    $ScanComputerForBlockedConnectionsButton = New-Object -TypeName "Windows.Forms.Button" -Property @{
        Margin = $ExportExistingRulesToPowerShellCommandsButton.Margin
        BackColor = "DarkSlateGray"
        ForeColor = "White"
        Font = $BoldButtonFont
    }
    $ScanComputerForBlockedConnectionsButton.Text = "Scan computer for blocked connections"
    $ScanComputerForBlockedConnectionsButton.Add_Click(
    {
        $ToolSelectionPageForm.Hide()
        ScanComputerForBlockedConnectionsPage
        $ToolSelectionPageForm.Show()   
    })
    $ScanComputerForBlockedConnectionsToolTip = New-Object -TypeName "System.Windows.Forms.ToolTip"
    $ScanComputerForBlockedConnectionsToolTip.SetToolTip($ScanComputerForBlockedConnectionsButton, "Use this tool to scan a computer for blocked network`nconnections and to create new firewall rules that can be`nsaved to a PowerShell script or saved to a group policy object.`n90% complete.")
    $ToolSelectionPageStatusBar = New-Object -TypeName "Windows.Forms.StatusBar" -Property @{
        Dock = "Bottom"
        Text = "Please select a tool to launch."
    }
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
