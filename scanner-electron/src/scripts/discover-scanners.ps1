# discover-scanners.ps1
# Enumerate WIA scanner devices and output JSON
# Usage: powershell -ExecutionPolicy Bypass -File discover-scanners.ps1

$ErrorActionPreference = 'Stop'

try {
    $deviceManager = New-Object -ComObject WIA.DeviceManager

    $scanners = @()

    foreach ($deviceInfo in $deviceManager.DeviceInfos) {
        # Type 1 = Scanner
        if ($deviceInfo.Type -eq 1) {
            $scanner = @{
                id           = $deviceInfo.DeviceID
                name         = $deviceInfo.Properties("Name").Value
                manufacturer = $deviceInfo.Properties("Manufacturer").Value
            }
            $scanners += $scanner
        }
    }

    $result = @{
        success  = $true
        scanners = $scanners
        count    = $scanners.Count
    }

    $result | ConvertTo-Json -Depth 3 -Compress
}
catch {
    $errorResult = @{
        success = $false
        error   = $_.Exception.Message
        scanners = @()
        count   = 0
    }
    $errorResult | ConvertTo-Json -Depth 3 -Compress
}
