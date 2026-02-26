# SlabTrack Scanner - WinRT scan via PowerShell
# Uses WIA COM to configure page size, then WinRT ImageScanner to scan
# Outputs JSON lines for streaming progress

param(
    [string]$OutputDir = "C:\temp\slabtrack-scans",
    [int]$Dpi = 300,
    [switch]$Duplex,
    [int]$MaxPages = 0,
    [string]$ScannerId = "",
    [string]$ColorMode = "Color",
    [double]$CardWidth = 2.5,
    [double]$CardHeight = 3.5
)

$ErrorActionPreference = "Stop"

function WriteJson($obj) {
    $json = $obj | ConvertTo-Json -Compress
    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}

function WriteStatus($status, $message) {
    WriteJson @{ event = "status"; status = $status; message = $message }
}

function WriteError($message) {
    WriteJson @{ event = "error"; error = $message }
}

function WritePage($pageNum, $filePath, $side) {
    WriteJson @{ event = "page_scanned"; page = $pageNum; path = $filePath; side = $side }
}

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Card dimensions (from params, defaults to 2.5" x 3.5" standard trading card)
$CardWidthInches = $CardWidth
$CardHeightInches = $CardHeight

# Calculate pixel extents for WIA (based on requested DPI)
$ExtentX = [int][math]::Round($CardWidthInches * $Dpi)
$ExtentY = [int][math]::Round($CardHeightInches * $Dpi)

WriteStatus "initializing" "Setting up scanner..."

# =====================================================
# Step 1: Configure WIA driver for small document size
# =====================================================
try {
    $dm = New-Object -ComObject WIA.DeviceManager
    $wiaScanner = $null

    foreach ($d in $dm.DeviceInfos) {
        if ($d.Type -eq 1 -or $d.Type -eq 65537 -or (($d.Type -band 1) -eq 1 -and $d.Type -ne 65535)) {
            if ($ScannerId -and $d.DeviceID -ne $ScannerId) { continue }
            $wiaScanner = $d.Connect()
            break
        }
    }

    if (-not $wiaScanner) {
        WriteError "No scanner found"
        exit 1
    }

    WriteStatus "configuring" "Configuring scanner via WIA..."

    $item = $wiaScanner.Items[1]

    # Set DPI on the scan item FIRST (extents depend on DPI)
    $actualWiaDpi = 150  # Default
    $dpiValues = @($Dpi, 600, 400, 300, 200, 150)
    foreach ($tryDpi in $dpiValues) {
        try {
            $item.Properties.Item("Horizontal Resolution").Value = $tryDpi
            $item.Properties.Item("Vertical Resolution").Value = $tryDpi
            $actualWiaDpi = $tryDpi
            break
        } catch {
            continue
        }
    }

    # Recalculate extents based on actual DPI
    $ExtentX = [int][math]::Round($CardWidthInches * $actualWiaDpi)
    $ExtentY = [int][math]::Round($CardHeightInches * $actualWiaDpi)

    # Set extents for card size (this is the critical step!)
    try {
        $item.Properties.Item("Horizontal Start Position").Value = 0
        $item.Properties.Item("Vertical Start Position").Value = 0
        $item.Properties.Item("Horizontal Extent").Value = $ExtentX
        $item.Properties.Item("Vertical Extent").Value = $ExtentY
    } catch {
        # If card-size extents fail, try a slightly larger region
        WriteStatus "warning" "Card extents failed, trying larger region..."
        try {
            $ExtentX = [int][math]::Round(3.0 * $actualWiaDpi)  # 3 inches wide
            $ExtentY = [int][math]::Round(4.0 * $actualWiaDpi)  # 4 inches tall
            $item.Properties.Item("Horizontal Extent").Value = $ExtentX
            $item.Properties.Item("Vertical Extent").Value = $ExtentY
        } catch {
            WriteStatus "warning" "Could not set card extents: $($_.Exception.Message)"
        }
    }

    # Set color mode on item
    # DataType: 0=BW, 1=Grayscale, 2=Threshold, 3=Color
    if ($ColorMode -eq "Grayscale") {
        try { $item.Properties.Item("Data Type").Value = 1 } catch {}
    } elseif ($ColorMode -eq "BW") {
        try { $item.Properties.Item("Data Type").Value = 0 } catch {}
    }
    # Default is Color (3), already set

    WriteStatus "configured" "WIA configured: ${ExtentX}x${ExtentY}px at ${Dpi}DPI"
} catch {
    WriteError "WIA configuration failed: $($_.Exception.Message)"
    exit 1
}

# =====================================================
# Step 2: Scan via WinRT ImageScanner API
# =====================================================
WriteStatus "loading" "Loading WinRT scanner API..."

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $null = [Windows.Devices.Scanners.ImageScanner,Windows.Devices.Scanners,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Scanners.ImageScannerScanSource,Windows.Devices.Scanners,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Scanners.ImageScannerScanResult,Windows.Devices.Scanners,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Enumeration.DeviceInformation,Windows.Devices.Enumeration,ContentType=WindowsRuntime]
    $null = [Windows.Devices.Enumeration.DeviceInformationCollection,Windows.Devices.Enumeration,ContentType=WindowsRuntime]
    $null = [Windows.Storage.StorageFolder,Windows.Storage,ContentType=WindowsRuntime]
} catch {
    WriteError "Failed to load WinRT: $($_.Exception.Message)"
    exit 1
}

# Async helpers
function AwaitOp($asyncOp, $resultType) {
    $m = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    })[0]
    $task = $m.MakeGenericMethod($resultType).Invoke($null, @($asyncOp))
    $task.Wait(30000) | Out-Null
    return $task.Result
}

function AwaitOpProgress($asyncOp, $resultType, $progressType) {
    $m = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperationWithProgress`2'
    })[0]
    $task = $m.MakeGenericMethod($resultType, $progressType).Invoke($null, @($asyncOp))
    try {
        $task.Wait(180000) | Out-Null  # 3 min timeout
        return $task.Result
    } catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        throw $inner
    }
}

# Find scanner via WinRT
WriteStatus "connecting" "Connecting to scanner..."

try {
    $selector = [Windows.Devices.Scanners.ImageScanner]::GetDeviceSelector()
    $devices = AwaitOp ([Windows.Devices.Enumeration.DeviceInformation]::FindAllAsync($selector)) ([Windows.Devices.Enumeration.DeviceInformationCollection])

    if ($devices.Count -eq 0) {
        WriteError "No scanners found via WinRT"
        exit 1
    }

    $targetDev = $null
    foreach ($dev in $devices) {
        if ($ScannerId -and $dev.Id -match [regex]::Escape($ScannerId)) {
            $targetDev = $dev
            break
        }
        if ($dev.Name -match "fi-8170") {
            $targetDev = $dev
            break
        }
    }
    if (-not $targetDev) { $targetDev = $devices[0] }

    $winrtScanner = AwaitOp ([Windows.Devices.Scanners.ImageScanner]::FromIdAsync($targetDev.Id)) ([Windows.Devices.Scanners.ImageScanner])

    if (-not $winrtScanner.IsScanSourceSupported([Windows.Devices.Scanners.ImageScannerScanSource]::Feeder)) {
        WriteError "Scanner does not support feeder/ADF"
        exit 1
    }

    WriteStatus "connected" "Connected to $($targetDev.Name)"
} catch {
    WriteError "Scanner connection failed: $($_.Exception.Message)"
    exit 1
}

# Configure WinRT feeder
$feeder = $winrtScanner.FeederConfiguration

# Set scan region to card size
$region = New-Object Windows.Foundation.Rect(0, 0, $CardWidthInches, $CardHeightInches)
$feeder.SelectedScanRegion = $region

# Set DPI via WinRT
try {
    $newRes = New-Object Windows.Devices.Scanners.ImageScannerResolution
    $newRes.DpiX = $Dpi
    $newRes.DpiY = $Dpi
    $feeder.DesiredResolution = $newRes
} catch {
    # Keep default DPI
}

# Set duplex
if ($Duplex) {
    try { $feeder.Duplex = $true } catch {}
}

# Set page count
if ($MaxPages -gt 0) {
    $feeder.MaxNumberOfPages = $MaxPages
} else {
    # 0 = scan all pages in feeder
    $feeder.MaxNumberOfPages = 0
}

$actualDpi = $feeder.ActualResolution.DpiX
$actualDuplex = $feeder.Duplex

WriteStatus "ready" "Ready: ${actualDpi}DPI, Duplex=$actualDuplex, Region=$($feeder.SelectedScanRegion.Width)x$($feeder.SelectedScanRegion.Height)"

# Get output folder
$storageFolder = AwaitOp ([Windows.Storage.StorageFolder]::GetFolderFromPathAsync($OutputDir)) ([Windows.Storage.StorageFolder])

# =====================================================
# Step 3: Execute scan
# =====================================================
WriteStatus "scanning" "Scanning..."

try {
    $scanOp = $winrtScanner.ScanFilesToFolderAsync(
        [Windows.Devices.Scanners.ImageScannerScanSource]::Feeder,
        $storageFolder
    )

    $result = AwaitOpProgress $scanOp ([Windows.Devices.Scanners.ImageScannerScanResult]) ([System.UInt32])

    WriteStatus "processing" "Scan complete, converting images..."

    # Load System.Drawing for BMP to JPEG conversion
    Add-Type -AssemblyName System.Drawing

    # Enumerate output files and convert BMP to JPEG
    $files = Get-ChildItem $OutputDir -File -Filter "*.bmp" | Sort-Object LastWriteTime
    $pageNum = 0

    foreach ($f in $files) {
        $pageNum++

        if ($actualDuplex) {
            $side = if ($pageNum % 2 -eq 1) { "front" } else { "back" }
        } else {
            $side = "front"
        }

        # Convert BMP to JPEG
        $jpgPath = $f.FullName -replace '\.bmp$', '.jpg'
        try {
            $bmp = [System.Drawing.Bitmap]::new($f.FullName)
            # Set JPEG quality to 95
            $jpegCodec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
            $qualityParam = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]95)
            $encoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
            $encoderParams.Param[0] = $qualityParam
            $bmp.Save($jpgPath, $jpegCodec, $encoderParams)
            $bmp.Dispose()

            # Remove original BMP
            Remove-Item $f.FullName -Force

            WritePage $pageNum $jpgPath $side
        } catch {
            # If conversion fails, use original BMP
            WriteStatus "warning" "JPEG conversion failed for page $pageNum, using BMP"
            WritePage $pageNum $f.FullName $side
        }
    }

    # Also check for any non-BMP files the scanner may have created
    $otherFiles = Get-ChildItem $OutputDir -File | Where-Object { $_.Extension -ne '.bmp' -and $_.Extension -ne '.jpg' } | Sort-Object LastWriteTime
    foreach ($f in $otherFiles) {
        $pageNum++
        $side = if ($actualDuplex -and $pageNum % 2 -eq 0) { "back" } else { "front" }
        WritePage $pageNum $f.FullName $side
    }

    WriteJson @{
        event = "scan_complete"
        totalPages = $pageNum
        duplex = $actualDuplex
        dpi = $actualDpi
        outputDir = $OutputDir
    }

    exit 0
} catch {
    $errMsg = $_.Message
    if (-not $errMsg) { $errMsg = $_.Exception.Message }
    if ($errMsg -match "Paper problem") {
        WriteError "Paper problem - check that cards are loaded in the feeder and the paper path is clear"
    } elseif ($errMsg -match "no documents") {
        WriteError "No documents in feeder - please load cards and try again"
    } else {
        WriteError "Scan failed: $errMsg"
    }
    exit 1
}
