# scan-wia.ps1
# Execute WIA scan with configurable settings
# Usage: powershell -ExecutionPolicy Bypass -File scan-wia.ps1 -ScannerId "..." -OutputDir "..." [-Dpi 300] [-ColorMode 1] [-Duplex] [-Source 1]
#
# ColorMode: 1=Color, 2=Grayscale, 4=B&W
# Source: 1=Flatbed, 2=Feeder (ADF)

param(
    [Parameter(Mandatory=$true)]
    [string]$ScannerId,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [int]$Dpi = 300,

    [int]$ColorMode = 1,

    [switch]$Duplex,

    [int]$Source = 2  # Default to ADF feeder
)

$ErrorActionPreference = 'Stop'

# WIA property constants
$WIA_DPS_DOCUMENT_HANDLING_SELECT = "3088"
$WIA_DPS_PAGES = "3096"
$WIA_IPA_DATATYPE = "4103"
$WIA_IPS_CUR_INTENT = "6146"
$WIA_IPS_XRES = "6147"
$WIA_IPS_YRES = "6148"
$WIA_IPS_PAGES = "3096"

$FEEDER = 0x001
$FLATBED = 0x002
$DUPLEX_FLAG = 0x004
$FRONT_ONLY = 0x008

function Write-JsonLine {
    param([hashtable]$Data)
    $json = $Data | ConvertTo-Json -Depth 3 -Compress
    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}

function Set-WiaProperty {
    param($Item, [string]$PropertyId, $Value)
    foreach ($prop in $Item.Properties) {
        if ($prop.PropertyID -eq $PropertyId) {
            $prop.Value = $Value
            return $true
        }
    }
    return $false
}

try {
    # Ensure output directory exists
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    Write-JsonLine @{ type = "status"; message = "Connecting to scanner..." }

    $deviceManager = New-Object -ComObject WIA.DeviceManager

    # Find the target scanner
    $device = $null
    foreach ($deviceInfo in $deviceManager.DeviceInfos) {
        if ($deviceInfo.DeviceID -eq $ScannerId) {
            $device = $deviceInfo.Connect()
            break
        }
    }

    if (-not $device) {
        Write-JsonLine @{ type = "error"; message = "Scanner not found: $ScannerId" }
        exit 1
    }

    $scannerName = $device.Properties("Name").Value
    Write-JsonLine @{ type = "status"; message = "Connected to $scannerName" }

    # Configure document handling (feeder vs flatbed, duplex)
    foreach ($prop in $device.Properties) {
        if ($prop.PropertyID -eq $WIA_DPS_DOCUMENT_HANDLING_SELECT) {
            $flags = $FEEDER
            if ($Source -eq 1) { $flags = $FLATBED }
            if ($Duplex) { $flags = $flags -bor $DUPLEX_FLAG }
            try { $prop.Value = $flags } catch {}
        }
        if ($prop.PropertyID -eq $WIA_DPS_PAGES) {
            try { $prop.Value = 0 } catch {}  # 0 = scan all pages in feeder
        }
    }

    # Get the first scan item
    $item = $device.Items[1]

    # Set resolution
    Set-WiaProperty -Item $item -PropertyId $WIA_IPS_XRES -Value $Dpi | Out-Null
    Set-WiaProperty -Item $item -PropertyId $WIA_IPS_YRES -Value $Dpi | Out-Null

    # Set color mode
    Set-WiaProperty -Item $item -PropertyId $WIA_IPA_DATATYPE -Value $ColorMode | Out-Null

    Write-JsonLine @{ type = "status"; message = "Starting scan (DPI: $Dpi, Duplex: $Duplex, Source: $(if($Source -eq 1){'Flatbed'}else{'ADF'}))" }

    $pageNum = 0
    $hasMorePages = $true

    while ($hasMorePages) {
        $pageNum++
        $side = if ($Duplex) { if ($pageNum % 2 -eq 1) { "front" } else { "back" } } else { "front" }

        Write-JsonLine @{ type = "scanning"; page = $pageNum; side = $side; message = "Scanning page $pageNum ($side)..." }

        try {
            # Transfer image
            $imageProcess = New-Object -ComObject WIA.ImageProcess
            $image = $item.Transfer("{B96B3CAE-0728-11D3-9D7B-0000F81EF32E}")  # JPEG format

            # Save to file
            $fileName = "page_${pageNum}.jpg"
            $filePath = Join-Path $OutputDir $fileName

            # Delete if exists
            if (Test-Path $filePath) { Remove-Item $filePath -Force }

            $image.SaveFile($filePath)

            $fileSize = (Get-Item $filePath).Length

            Write-JsonLine @{
                type     = "page_scanned"
                page     = $pageNum
                side     = $side
                file     = $filePath
                fileName = $fileName
                size     = $fileSize
            }
        }
        catch [System.Runtime.InteropServices.COMException] {
            # WIA_ERROR_PAPER_EMPTY (0x80210003) means no more pages
            if ($_.Exception.HResult -eq -2145320957 -or $_.Exception.Message -match "paper" -or $_.Exception.Message -match "no more") {
                $hasMorePages = $false
                Write-JsonLine @{ type = "status"; message = "No more pages in feeder" }
            } else {
                throw
            }
        }
        catch {
            # Check for feeder empty condition
            if ($_.Exception.Message -match "paper|empty|no document|feeder") {
                $hasMorePages = $false
                Write-JsonLine @{ type = "status"; message = "Feeder empty" }
            } else {
                throw
            }
        }
    }

    Write-JsonLine @{
        type       = "scan_complete"
        totalPages = $pageNum - 1
        outputDir  = $OutputDir
    }
}
catch {
    Write-JsonLine @{
        type    = "error"
        message = $_.Exception.Message
        detail  = $_.ScriptStackTrace
    }
    exit 1
}
