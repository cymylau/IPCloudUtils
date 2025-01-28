@{
    # Module metadata
    ModuleVersion     = '0.0.1'
    GUID              = 'D3AC5A1B-BFA6-4B7C-8A6D-45F23C8FDD99'
    Author            = 'Rich J'
    CompanyName       = 'cymylau'
    Copyright         = '(c) cymylau. All rights reserved.'
    Description       = 'A PowerShell module for IP address validation, cloud identification, and HTTP testing.'
    PowerShellVersion = '7.4.0'

    # Script/module paths
    RootModule        = 'IPCloudUtils.psm1'

    # Functions to export
    FunctionsToExport = @(
        'Test-IpInSubnet',
        'Test-IpInMultipleSubnets',
        'Test-IPv4Routable',
        'Test-IPv4Azure',
        'Test-IPv4GCP',
        'Test-HTTPResponse'
    )

    # Cmdlets to export (none in this case)
    CmdletsToExport   = @()

    # Aliases to export (none in this case)
    AliasesToExport   = @()

    # Private data
    PrivateData       = @{
        PSData = @{
            Tags         = @('IP', 'Cloud', 'Networking', 'Azure', 'GCP', 'HTTP')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/YourGitHubUsername/IPCloudUtils'
        }
    }
}
