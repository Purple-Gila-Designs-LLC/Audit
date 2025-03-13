# Requires Microsoft.Graph module
# This script assumes that you have the Microsoft.Graph module installed.  If not, please install using the following cmdlet
# Install-Module -Name Microsoft.Graph -Repository PSGallery -Scope AllUsers -Force -AllowClobber

Add-Type -AssemblyName PresentationFramework

# Create the GUI window
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Global Admins Exporter" Height="200" Width="400">
    <Grid>
        <Button Name="ExportButton" Content="Export to CSV" HorizontalAlignment="Center" VerticalAlignment="Center" Width="150" Height="50"/>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Event handler for the Export button
$window.FindName("ExportButton").Add_Click({
    # Connect to Microsoft Graph (Manual Auth)
    Connect-MgGraph

    # Set ID for Global Admin Role
    $globalAdmin = "68f97962-6168-438e-82ca-ee2fa01a40c3"

    # List active Global Administrators
    $activeAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdmin | ForEach-Object {
        Get-MgUser -UserId $_.Id
    }

    # List eligible Global Administrators (via Privileged Identity Management)
    $eligibleAdmins = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'" | ForEach-Object {
        Get-MgUser -UserId $_.principalId
    }

    # Combine results
    $allAdmins = $activeAdmins + $eligibleAdmins

    # Export to CSV
    $csvPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("Desktop"), "GlobalAdmins.csv")
    $allAdmins | Select-Object Id, DisplayName, UserPrincipalName, CreatedDateTime, AccountEnabled | Export-Csv -Path $csvPath -NoTypeInformation

    # Show message box
    [System.Windows.MessageBox]::Show("CSV file has been exported to your Desktop: $csvPath", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})

# Show the window
$window.ShowDialog()