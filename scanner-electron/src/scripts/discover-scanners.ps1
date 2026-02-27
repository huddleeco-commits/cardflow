# discover-scanners.ps1
# Enumerate WIA scanner devices and output JSON
# Usage: powershell -ExecutionPolicy Bypass -File discover-scanners.ps1

$ErrorActionPreference = 'Stop'

try {
    $deviceManager = New-Object -ComObject WIA.DeviceManager

    $scanners = @()

    foreach ($deviceInfo in $deviceManager.DeviceInfos) {
        # Type 1 = Scanner, but WIA can report flags like 0x10001 (65537) for feeder scanners
        # Check if bit 0 is set (scanner) — exclude type 2 (camera) and unknown (65535)
        $devType = $deviceInfo.Type
        if ($devType -eq 1 -or $devType -eq 65537 -or ($devType -band 1) -eq 1 -and $devType -ne 65535) {
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
