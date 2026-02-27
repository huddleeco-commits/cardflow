# scan-wia.ps1 — Scan ONE sheet from fi-8170 via WIA COM
# Called repeatedly by main.js until feeder is empty.
# ZERO property changes — fi-8170 breaks if you touch anything.
# With duplex enabled in Scanner Setup, Transfer() returns front then back.
param(
    [Parameter(Mandatory=$true)]
    [string]$ScannerId,

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [int]$PageOffset = 0,
    [switch]$Duplex
)

$ErrorActionPreference = 'Stop'

function Write-JsonLine {
    param([hashtable]$Data)
    $json = $Data | ConvertTo-Json -Depth 3 -Compress
    [Console]::Out.WriteLine($json)
    [Console]::Out.Flush()
}

try {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $deviceManager = New-Object -ComObject WIA.DeviceManager
    $device = $null
    foreach ($deviceInfo in $deviceManager.DeviceInfos) {
        if ($deviceInfo.DeviceID -eq $ScannerId) {
            $device = $deviceInfo.Connect()
            break
        }
    }

    if (-not $device) {
        Write-JsonLine @{ event = "error"; error = "Scanner not found"; message = "Scanner not found" }
        exit 1
    }

    $item = $device.Items[1]

    # JPEG converter
    $imageProcess = New-Object -ComObject WIA.ImageProcess
    $imageProcess.Filters.Add($imageProcess.FilterInfos("Convert").FilterID)
    $imageProcess.Filters[1].Properties("FormatID").Value = "{B96B3CAE-0728-11D3-9D7B-0000F81EF32E}"
    $imageProcess.Filters[1].Properties("Quality").Value = 85

    $pageNum = $PageOffset
    $scanning = $true

    while ($scanning) {
        $pageNum++
        $side = if ($Duplex) { if (($pageNum - $PageOffset) % 2 -eq 1) { "front" } else { "back" } } else { "front" }

        try {
            $image = $item.Transfer()
            $jpegImage = $imageProcess.Apply($image)

            $fileName = "page_${pageNum}.jpg"
            $filePath = Join-Path $OutputDir $fileName
            if (Test-Path $filePath) { Remove-Item $filePath -Force }
            $jpegImage.SaveFile($filePath)

            $fileSize = (Get-Item $filePath).Length

            Write-JsonLine @{
                event    = "page_scanned"
                page     = $pageNum
                side     = $side
                path     = $filePath
                fileName = $fileName
                size     = $fileSize
            }
        }
        catch {
            # Any error after first Transfer = done with this sheet
            $scanning = $false
            $hresult = ""
            if ($_.Exception -is [System.Runtime.InteropServices.COMException]) {
                $hresult = "0x{0:X8}" -f $_.Exception.HResult
            }
            $errMsg = $_.Exception.Message
            $isEmpty = ($errMsg -match "paper|empty|no document|feeder|no more") -or
                       ($hresult -eq "0x80210003") -or ($hresult -eq "0x80210010")

            if ($isEmpty -and $pageNum -eq ($PageOffset + 1)) {
                # First Transfer failed = feeder truly empty
                Write-JsonLine @{ event = "feeder_empty"; message = "No paper in feeder" }
                exit 0
            }
            # Otherwise we got some pages, sheet is done
        }
    }

    Write-JsonLine @{
        event      = "sheet_done"
        pagesThisSheet = $pageNum - $PageOffset
        lastPage   = $pageNum
    }
}
catch {
    Write-JsonLine @{
        event   = "error"
        error   = $_.Exception.Message
        message = $_.Exception.Message
    }
    exit 1
}
