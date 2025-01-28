function Test-IpInSubnet {
    <#
    .SYNOPSIS
    Checks if a given IP address falls within a specified subnet in CIDR format.

    .DESCRIPTION
    This function takes an IPv4 address and a subnet in CIDR notation as inputs.
    It calculates whether the IP address belongs to the given subnet range by comparing the network ID of the IP address with that of the subnet.

    .PARAMETER IPAddress
    The IPv4 address to be checked. Must be a valid IPv4 address.

    .PARAMETER Subnet
    The subnet in CIDR format (e.g., 192.168.1.0/24). Must be a valid subnet declaration.

    .EXAMPLE
    Test-IpInSubnet -IPAddress "192.168.1.10" -Subnet "192.168.1.0/24"

    Checks if the IP address 192.168.1.10 belongs to the subnet 192.168.1.0/24.
    Outputs true if it belongs, false otherwise.

    .EXAMPLE
    Test-IpInSubnet -IPAddress "10.0.0.1" -Subnet "192.168.1.0/24"

    Checks if the IP address 10.0.0.1 belongs to the subnet 192.168.1.0/24.
    Outputs false as it does not belong.

    .EXAMPLE
    Test-IpInSubnet -IPAddress "172.16.0.5" -Subnet "172.16.0.0/16"

    Checks if the IP address 172.16.0.5 belongs to the subnet 172.16.0.0/16.
    Outputs true as it belongs to the subnet.

    .NOTES
    - The function uses bitwise operations to compute the network ID and compare it with the subnet range.
    - Ensure that both the IP address and subnet are valid before running the function.

    .OUTPUTS
    System.Boolean
    Returns $true if the IP address belongs to the subnet, $false otherwise.

    .LINK
    Test-IpInMultipleSubnets
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ [System.Net.IPAddress]::TryParse($_, [ref]$null) })]
        [string]$IPAddress,

        [Parameter(Mandatory, Position = 1)]
        [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$')]
        [string]$Subnet
    )

    process {
        # Split subnet into base IP and prefix length
        $subnetParts = $Subnet -split '/'
        $baseIP = $subnetParts[0]
        $prefixLength = [int]$subnetParts[1]

        # Convert the base IP and input IP to 32-bit integers
        $baseIPBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
        $inputIPBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()

        # Reverse byte arrays manually (to match endianness)
        $baseIPInt = [BitConverter]::ToUInt32($baseIPBytes[3..0], 0)
        $inputIPInt = [BitConverter]::ToUInt32($inputIPBytes[3..0], 0)

        # Create a subnet mask based on the prefix length
        $subnetMask = ([math]::Pow(2, $prefixLength) - 1) * [math]::Pow(2, 32 - $prefixLength)

        # Calculate the network ID for the input IP and the base subnet
        $networkIDBase = $baseIPInt -band [uint32]$subnetMask
        $networkIDInput = $inputIPInt -band [uint32]$subnetMask

        # Check if the network IDs match
        if ($networkIDBase -eq $networkIDInput) {
            Write-Output "$IPAddress is within the subnet $Subnet."
            return $true
        } else {
            Write-Output "$IPAddress is NOT within the subnet $Subnet."
            return $false
        }
    }
}

function Test-IpInMultipleSubnets {
    <#
    .SYNOPSIS
    Checks if a single IP address belongs to any of the provided subnets.

    .DESCRIPTION
    This function takes a single IPv4 address and an array of subnets in CIDR format.
    It checks if the IP address falls within any of the subnets provided and stops as soon as a match is found.
    If a valid match is found, it outputs the result and stops further processing.

    .PARAMETER IPAddress
    The IPv4 address to be checked. Must be a valid IPv4 address.

    .PARAMETER Subnets
    An array of subnets in CIDR format (e.g., 192.168.1.0/24, 10.0.0.0/8).

    .EXAMPLE
    Test-IpInMultipleSubnets -IPAddress "192.168.1.10" -Subnets @("192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/16")

    Checks if 192.168.1.10 belongs to any of the three subnets. If found in the first subnet, stops further processing.

    .EXAMPLE
    Test-IpInMultipleSubnets -IPAddress "10.0.0.1" -Subnets @("192.168.1.0/24", "172.16.0.0/16")

    Checks if 10.0.0.1 belongs to the subnets. Since it's not in any of the ranges, the function will process all subnets and return false.

    .EXAMPLE
    Test-IpInMultipleSubnets -IPAddress "192.168.1.15" -Subnets @("192.168.1.0/24")

    Checks if 192.168.1.15 belongs to the subnet 192.168.1.0/24. Outputs true if it belongs.

    .NOTES
    - Invalid subnet formats are skipped with a warning.
    - The function stops as soon as a match is found, making it efficient for large subnet lists.

    .OUTPUTS
    System.Boolean
    Returns $true if the IP address matches any subnet. Returns $false otherwise.

    .LINK
    Test-IpInSubnet
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ [System.Net.IPAddress]::TryParse($_, [ref]$null) })]
        [string]$IPAddress,

        [Parameter(Mandatory, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Subnets
    )

    process {
        foreach ($subnet in $Subnets) {
            if ($subnet -notmatch '^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$') {
                Write-Warning "Invalid subnet format: $subnet. Skipping."
                continue
            }

            $inSubnet = Test-IpInSubnet -IPAddress $IPAddress -Subnet $subnet

            if ($inSubnet) {
                Write-Output "$IPAddress is within the subnet $subnet."
                return $true
            }
        }

        # If no valid subnet matches, return false
        Write-Output "$IPAddress does not fall within any of the provided subnets."
        return $false
    }
}
function Test-IPv4Routable {
    <#
    .SYNOPSIS
    Checks if an IPv4 address is a valid, internet-routable address.

    .DESCRIPTION
    This function validates whether an IPv4 address is internet-routable.
    It excludes RFC1918 private addresses, reserved addresses, and special-use ranges
    as defined by the IANA IPv4 Special-Purpose Address Registry.

    .PARAMETER IPAddress
    The IPv4 address to validate. Must be a valid IPv4 address.

    .EXAMPLE
    Test-IPv4Routable -IPAddress "8.8.8.8"

    Returns true as 8.8.8.8 is an internet-routable address.

    .EXAMPLE
    Test-IPv4Routable -IPAddress "192.168.1.1"

    Returns false as 192.168.1.1 is an RFC1918 private address.

    .EXAMPLE
    Test-IPv4Routable -IPAddress "224.0.0.1"

    Returns false as 224.0.0.1 is a reserved multicast address.

    .NOTES
    - The function uses specific address ranges defined in IANA's registry.
    - Reserved and private addresses are explicitly excluded.

    .OUTPUTS
    System.Boolean
    Returns $true if the IP is routable, $false otherwise.

    .LINK
    https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ [System.Net.IPAddress]::TryParse($_, [ref]$null) })]
        [string]$IPAddress
    )

    process {
        # Convert the IP address to an unsigned 32-bit integer
        $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
        $ipInt = [BitConverter]::ToUInt32($ipBytes[3..0], 0)

        # Define non-routable ranges (start and end as 32-bit integers)
        $nonRoutableRanges = @(
            # RFC1918 Private Addresses
            @{ Start = 0x0A000000; End = 0x0AFFFFFF }, # 10.0.0.0/8
            @{ Start = 0xAC100000; End = 0xAC1FFFFF }, # 172.16.0.0/12
            @{ Start = 0xC0A80000; End = 0xC0A8FFFF }, # 192.168.0.0/16
            
            # Reserved Addresses
            @{ Start = 0x00000000; End = 0x000000FF }, # 0.0.0.0/8
            @{ Start = 0x7F000000; End = 0x7FFFFFFF }, # 127.0.0.0/8 (Loopback)
            @{ Start = 0xA9FE0000; End = 0xA9FEFFFF }, # 169.254.0.0/16 (Link-local)
            @{ Start = 0xE0000000; End = 0xEFFFFFFF }, # 224.0.0.0/4 (Multicast)
            @{ Start = 0xF0000000; End = 0xFFFFFFFF }  # 240.0.0.0/4 (Reserved for future use)
        )

        # Check if the IP falls within any of the non-routable ranges
        foreach ($range in $nonRoutableRanges) {
            if ($ipInt -ge $range.Start -and $ipInt -le $range.End) {
                Write-Output "$IPAddress is not internet-routable (non-routable range)."
                return $false
            }
        }

        # If no match in non-routable ranges, it's internet-routable
        Write-Output "$IPAddress is internet-routable."
        return $true
    }
}

function Test-IPv4Azure {
    <#
    .SYNOPSIS
    Checks if an IPv4 address belongs to Microsoft Azure and provides the service name if there's a match.

    .DESCRIPTION
    This function checks if an IPv4 address is part of Microsoft Azure's public IP ranges.
    It fetches the latest list of Azure IP ranges published by Microsoft and determines if the IP falls within any range.
    If a match is found, the function also outputs the Azure service name associated with the subnet.

    .PARAMETER IPAddress
    The IPv4 address to check. Must be a valid IPv4 address.

    .EXAMPLE
    Test-IPv4Azure -IPAddress "20.42.0.1"

    Checks if 20.42.0.1 belongs to Microsoft Azure. Returns true and the associated service name if it does.

    .EXAMPLE
    Test-IPv4Azure -IPAddress "192.168.1.1"

    Checks if 192.168.1.1 belongs to Microsoft Azure. Returns false as it is not an Azure IP.

    .NOTES
    - The function fetches Azure's IP ranges dynamically from Microsoft's JSON file:
      https://www.microsoft.com/en-us/download/details.aspx?id=56519
    - Make sure the system has internet access when running the function.

    .OUTPUTS
    System.Object
    Outputs a PSCustomObject with the properties:
      - IPAddress
      - IsAzureIP
      - ServiceName

    .LINK
    https://www.microsoft.com/en-us/download/details.aspx?id=56519
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ [System.Net.IPAddress]::TryParse($_, [ref]$null) })]
        [string]$IPAddress
    )

    process {
        try {
            # Download the Azure IP ranges JSON file
            $url = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
            $jsonFilePath = (Invoke-WebRequest -Uri $url -UseBasicParsing).Links |
                Where-Object { $_.href -match '\.json$' } |
                Select-Object -ExpandProperty href
            if (-not $jsonFilePath) {
                Write-Error "Failed to locate the Azure JSON file link."
                return
            }

            $jsonData = Invoke-WebRequest -Uri $jsonFilePath -UseBasicParsing | ConvertFrom-Json

            # Convert input IP address to 32-bit integer
            $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            $ipInt = [BitConverter]::ToUInt32($ipBytes[3..0], 0)

            # Check if the IP belongs to any Azure range
            foreach ($entry in $jsonData.values) {
                $entry.properties
                $serviceName = $entry.properties.systemService
                $addressPrefixes = $entry.properties.addressPrefixes

                foreach ($range in $addressPrefixes) {
                    if ($range -notmatch '^\d+\.\d+\.\d+\.\d+/\d+$') {
                        continue
                    }

                    $subnetParts = $range -split '/'
                    $subnetBase = $subnetParts[0]
                    $prefixLength = [int]$subnetParts[1]

                    # Convert the subnet base IP to a 32-bit integer
                    $subnetBytes = [System.Net.IPAddress]::Parse($subnetBase).GetAddressBytes()
                    $subnetInt = [BitConverter]::ToUInt32($subnetBytes[3..0], 0)

                    # Create the subnet mask
                    $subnetMask = ([math]::Pow(2, $prefixLength) - 1) * [math]::Pow(2, 32 - $prefixLength)

                    # Check if the input IP falls in the range
                    if (($ipInt -band $subnetMask) -eq ($subnetInt -band $subnetMask)) {
                        Write-Output [pscustomobject]@{
                            IPAddress   = $IPAddress
                            IsAzureIP   = $true
                            ServiceName = $serviceName
                        }
                        return
                    }
                }
            }

            # If no match is found
            Write-Output [pscustomobject]@{
                IPAddress   = $IPAddress
                IsAzureIP   = $false
                ServiceName = $null
            }
        }
        catch {
            Write-Error "An error occurred: $_"
        }
    }
}

function Test-IPv4GCP {
    <#
    .SYNOPSIS
    Checks if an IPv4 address belongs to Google Cloud Platform (GCP) and provides the service name if there is a match.

    .DESCRIPTION
    This function checks if an IPv4 address is part of Google Cloud Platform's public IP ranges.
    It fetches the latest list of GCP IP ranges published by Google and determines if the IP falls within any range.
    If a match is found, the function outputs the service or description associated with the range.

    .PARAMETER IPAddress
    The IPv4 address to check. Must be a valid IPv4 address.

    .EXAMPLE
    Test-IPv4GCP -IPAddress "35.190.247.1"

    Checks if 35.190.247.1 belongs to Google Cloud Platform. Returns true and the associated service name if it does.

    .EXAMPLE
    Test-IPv4GCP -IPAddress "192.168.1.1"

    Checks if 192.168.1.1 belongs to Google Cloud Platform. Returns false as it is not a GCP IP.

    .NOTES
    - The function fetches GCP's IP ranges dynamically from Google's JSON file:
      https://www.gstatic.com/ipranges/cloud.json
    - Ensure the system has internet access when running the function.

    .OUTPUTS
    System.Object
    Outputs a PSCustomObject with the properties:
      - IPAddress
      - IsGCPIP
      - ServiceName

    .LINK
    https://www.gstatic.com/ipranges/cloud.json
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ [System.Net.IPAddress]::TryParse($_, [ref]$null) })]
        [string]$IPAddress
    )

    process {
        try {
            # Download the GCP IP ranges JSON file
            $url = "https://www.gstatic.com/ipranges/cloud.json"
            $jsonData = Invoke-WebRequest -Uri $url -UseBasicParsing | ConvertFrom-Json

            # Convert input IP address to 32-bit integer
            $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            $ipInt = [BitConverter]::ToUInt32($ipBytes[3..0], 0)

            # Check if the IP belongs to any GCP range
            foreach ($entry in $jsonData.prefixes) {
                $range = $entry.ipv4Prefix
                $serviceName = $entry.service

                if ($null -eq $range) {
                    continue
                }

                if ($range -notmatch '^\d+\.\d+\.\d+\.\d+/\d+$') {
                    continue
                }

                $subnetParts = $range -split '/'
                $subnetBase = $subnetParts[0]
                $prefixLength = [int]$subnetParts[1]

                # Convert the subnet base IP to a 32-bit integer
                $subnetBytes = [System.Net.IPAddress]::Parse($subnetBase).GetAddressBytes()
                $subnetInt = [BitConverter]::ToUInt32($subnetBytes[3..0], 0)

                # Create the subnet mask
                $subnetMask = ([math]::Pow(2, $prefixLength) - 1) * [math]::Pow(2, 32 - $prefixLength)

                # Check if the input IP falls in the range
                if (($ipInt -band $subnetMask) -eq ($subnetInt -band $subnetMask)) {
                    Write-Output [pscustomobject]@{
                        IPAddress   = $IPAddress
                        IsGCPIP     = $true
                        ServiceName = $serviceName
                    }
                    return
                }
            }

            # If no match is found
            Write-Output [pscustomobject]@{
                IPAddress   = $IPAddress
                IsGCPIP     = $false
                ServiceName = $null
            }
        }
        catch {
            Write-Error "An error occurred: $_"
        }
    }
}

function Test-HTTPResponse {
    <#
    .SYNOPSIS
    Sends HTTP and HTTPS requests to an IP address and returns the HTTP response codes, with a precheck to verify if the ports are open.

    .DESCRIPTION
    This function performs prechecks using TCP connections to verify if port 80 (HTTP) and port 443 (HTTPS) are open on the target IP address.
    If the ports are open, it performs HTTP and HTTPS GET requests without following redirects and returns the response codes.

    .PARAMETER IPAddress
    The IP address to test. Must be a valid IPv4 or IPv6 address.

    .EXAMPLE
    Test-HTTPResponse -IPAddress "93.184.216.34"

    Checks if ports 80 and 443 are open on 93.184.216.34, then sends HTTP and HTTPS requests and returns the HTTP response codes.

    .EXAMPLE
    Test-HTTPResponse -IPAddress "192.168.1.1"

    Checks if ports 80 and 443 are open on 192.168.1.1 (e.g., a local router), then returns the HTTP response codes.

    .NOTES
    - The function does not follow redirects during HTTP/HTTPS requests.
    - If a port is closed, the function skips the request for that protocol and notes it in the output.

    .OUTPUTS
    PSCustomObject
    Outputs a custom object with the following properties:
      - IPAddress
      - HTTPPortOpen
      - HTTPResponseCode
      - HTTPSPortOpen
      - HTTPSResponseCode

    .LINK
    Invoke-WebRequest
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ [System.Net.IPAddress]::TryParse($_, [ref]$null) })]
        [string]$IPAddress
    )

    process {
        # Helper function to check if a TCP port is open
        function Test-TCPPort {
            param (
                [Parameter(Mandatory)]
                [string]$IPAddress,

                [Parameter(Mandatory)]
                [int]$Port
            )

            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($IPAddress, $Port)
                $tcpClient.Close()
                return $true
            }
            catch {
                return $false
            }
        }

        # Initialize variables to store results
        $httpPortOpen = $false
        $httpsPortOpen = $false
        $httpCode = "Not Tested"
        $httpsCode = "Not Tested"

        # Check if TCP port 80 (HTTP) is open
        if (Test-TCPPort -IPAddress $IPAddress -Port 80) {
            $httpPortOpen = $true
        }

        # Check if TCP port 443 (HTTPS) is open
        if (Test-TCPPort -IPAddress $IPAddress -Port 443) {
            $httpsPortOpen = $true
        }

        # Perform HTTP request if port 80 is open
        if ($httpPortOpen) {
            try {
                $httpResponse = Invoke-WebRequest -Uri "http://$IPAddress" -UseBasicParsing -Method Get -TimeoutSec 10 -MaximumRedirection 0
                $httpCode = $httpResponse.StatusCode
            }
            catch {
                $httpCode = "Error: $($_.Exception.Message)"
            }
        }

        # Perform HTTPS request if port 443 is open
        if ($httpsPortOpen) {
            try {
                $httpsResponse = Invoke-WebRequest -Uri "https://$IPAddress" -UseBasicParsing -Method Get -TimeoutSec 10 -MaximumRedirection 0
                $httpsCode = $httpsResponse.StatusCode
            }
            catch {
                $httpsCode = "Error: $($_.Exception.Message)"
            }
        }

        # Output the results as a custom object
        [pscustomobject]@{
            IPAddress         = $IPAddress
            HTTPPortOpen      = $httpPortOpen
            HTTPResponseCode  = $httpCode
            HTTPSPortOpen     = $httpsPortOpen
            HTTPSResponseCode = $httpsCode
        }
    }
}
