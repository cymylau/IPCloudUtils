# IPCloudUtils

**IPCloudUtils** is a PowerShell module designed to simplify tasks related to IP address validation, cloud provider identification, and HTTP/HTTPS connectivity testing. Whether you're managing cloud networks, troubleshooting connectivity, or validating public IPs, this module provides the tools you may need, this is currently experimental. 

Tested with PowerShell Core 7.4.0 

---

## Features

### 🌐 IP Address Validation
- Check if an IP address is valid and routable.
- Verify if an IP is private (RFC1918) or reserved.

### ☁️ Cloud IP Identification
- Determine if an IP belongs to **Microsoft Azure** or **Google Cloud Platform (GCP)**.
- Fetch and parse official cloud provider IP ranges dynamically.
- Identify the cloud service associated with a given IP.

### 🔍 HTTP/HTTPS Testing
- Test HTTP and HTTPS connectivity to an IP address.
- Retrieve HTTP response codes for both protocols.
- Perform prechecks to verify if ports 80 (HTTP) and 443 (HTTPS) are open before sending requests.

---

## Installation

1. Clone the repository or download the module:
    ```bash
    git clone https://github.com/cymylau/IPCloudUtils.git
    ```
2. Import the module in PowerShell:
    ```powershell
    Import-Module ./IPCloudUtils/IPCloudUtils.psm1
    ```
3. Verify installation:
    ```powershell
    Get-Command -Module IPCloudUtils
    ```

---

## Functions

### **Test-IpInSubnet**
- **Description**: Checks if an IP address belongs to a specific subnet.
- **Example**:
    ```powershell
    Test-IpInSubnet -IPAddress "192.168.1.10" -Subnet "192.168.1.0/24"
    ```

### **Test-IpInMultipleSubnets**
- **Description**: Checks if an IP address belongs to any subnet in a list of subnets.
- **Example**:
    ```powershell
    $subnets = @("192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12")
    Test-IpInMultipleSubnets -IPAddress "192.168.1.10" -Subnets $subnets
    ```

### **Test-IPv4Routable**
- **Description**: Determines if an IPv4 address is valid and internet-routable.
- **Example**:
    ```powershell
    Test-IPv4Routable -IPAddress "8.8.8.8"
    ```

### **Test-IPv4Azure**
- **Description**: Checks if an IPv4 address belongs to Microsoft Azure and retrieves the associated service name.
- **Example**:
    ```powershell
    Test-IPv4Azure -IPAddress "20.42.0.1"
    ```

### **Test-IPv4GCP**
- **Description**: Checks if an IPv4 address belongs to Google Cloud Platform (GCP) and retrieves the associated service name.
- **Example**:
    ```powershell
    Test-IPv4GCP -IPAddress "35.190.247.1"
    ```

### **Test-HTTPResponse**
- **Description**: Sends HTTP and HTTPS requests to an IP address and returns the response codes.
- **Features**:
  - Checks if ports 80 (HTTP) and 443 (HTTPS) are open before sending requests.
  - Does not follow redirects.
- **Example**:
    ```powershell
    Test-HTTPResponse -IPAddress "93.184.216.34"
    ```

---

## Requirements

- **PowerShell 7+**
- Internet access for functions that fetch cloud provider IP ranges.

---

## Contribution

We welcome contributions! If you’d like to add new features or improve existing functionality:
1. Fork the repository.
2. Create a new branch.
3. Submit a pull request.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgments

- Official Microsoft Azure IP ranges: [Download Center](https://www.microsoft.com/en-us/download/details.aspx?id=56519)
- Official Google Cloud IP ranges: [Cloud JSON](https://www.gstatic.com/ipranges/cloud.json)
