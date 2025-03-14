##############################
# GATHER TOOLS
##############################

# Requires Microsoft.Entra module
# This script assumes that you have the Microsoft.Entra module installed. If not, please install using the following cmdlet
# Install-Module -Name Microsoft.Entra -Repository PSGallery -Scope AllUsers -Force -AllowClobber

# Import the Microsoft Entra PowerShell module
Import-Module Microsoft.Entra

Add-Type -AssemblyName PresentationFramework

# Create the GUI window
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Entra Users Exporter" Height="200" Width="400">
    <Grid>
        <Button Name="ExportButton" Content="Export to CSV" HorizontalAlignment="Center" VerticalAlignment="Center" Width="150" Height="50"/>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Event handler for the Export button
$window.FindName("ExportButton").Add_Click({
    # Connect to Microsoft Entra ID
    Connect-Entra -Scopes "User.Read.All", "RoleManagement.Read.All", "Directory.Read.All"

    ##############################################
    # SET VARIABLES
    ##############################################
    $formattedDate = Get-Date -Format "yyyy-MM-dd"

    # Get the path to the current user's desktop
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')

    ###############################################################################################

    # Query for all active users excluding guest or external users
    $activeUsers = Get-EntraUser -Filter "accountEnabled eq true and userType eq 'Member'" -All
    Write-Host "Generating your report, EntraID - Active Users and Roles, please wait... " -ForegroundColor Blue
    Write-Host "Querying EntraID... Gathering all active users and their assigned roles. This may take some time!" -ForegroundColor Blue

    # Initialize an array to store user details with roles
    $userDetailsWithRoles = @()

    # Loop through each active user to get their assigned roles
    foreach ($user in $activeUsers) {
        $userRoles = Get-EntraUserRole -UserId $user.UserPrincipalName
        $roles = $userRoles | ForEach-Object { $_.DisplayName }
        
        # Create a custom object to store user details and roles
        $userDetails = [PSCustomObject]@{
            DisplayName = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Roles = $roles -join ", "
        }
        
        # Add the user details to the array
        $userDetailsWithRoles += $userDetails
    }
    ###################################################################################################
    #Create a CSV File
    $csvFile = "$desktopPath/$formattedDate-QuarterlyAuditReport_EntraID_ActiveUsersandRoles.csv"
    New-Item -Path $csvFile -ItemType File -Force

    # Export the user details with roles to a CSV file
    $userDetailsWithRoles | Export-Csv -Path "$csvFile" -NoTypeInformation

    # Show message box
    [System.Windows.MessageBox]::Show("CSV file has been exported to your Desktop: $csvFile", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
})

# Show the window
$window.ShowDialog()

