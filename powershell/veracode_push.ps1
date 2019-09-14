#!powershell


<#
.SYNOPSIS
PowerShell script for pushing binaries to Veracode using Java API.

.DESCRIPTION
The script pushes binaries to Veracode to run security scans using their Java API wrapper tool.
If the Veracode application id does not exist, this script will attempt to create an application id
and then try to push the binary to Veracode. This script will use the current date as the name
of the scan if one is not provided. Finally, this script is designed to push a single file. Refer
to Veracodes documentation on artifact format required for initializing scans for your application type.

.PARAMETER file
Path to the binary or artifact you wish to push to Veracode for scan.

.PARAMETER app
The name of the application defined within Veracode.

.PARAMETER sandbox
The name of a sandbox to scan within. OPTIONAL.

.PARAMETER scan
Desired name of this scan. OPTIONAL.

.EXAMPLE
./veracode_push.ps1 -file "C:\path\to\binary.bin" -app "My Application" -sandbox "My Sandbox" -scan "APP_SCAN_123"
#>

Param (
	[Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$file=$(throw "file is mandatory. Please provide path to artifact you wish to push to Veracode."),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$app=$(throw "app is mandatory. Please provide the Veracode-provided name of your application."),

    [Parameter()]
    [AllowNull()]
    [string]$sandbox,

    [Parameter()]
    [AllowNull()]
    [string]$scan
)

# Determine script location.
$workingDirectory = Split-Path $script:MyInvocation.MyCommand.Path

# Veracode Configuration Settings
$prescanSleepTime = 60
$scanSleepTime = 120
$javaWrapper = Join-Path -Path $workingDirectory -ChildPath ".\VeracodeJavaAPI.jar"
[string]$randomName = Get-Random
$outputFileName = Join-Path -Path $workingDirectory -ChildPath ($randomName + ".log")
$apiId = ""
$apiKey = ""
$proxyInfo = ""

Function Get-ScanName($scan) {
    If ($scan -eq $null -or $scan -eq "") {
        $scan = Get-Date -UFormat "%Y-%m-%d-%T"
        Write-Host "[INFO] No scan name provided. Using $scan."
    }
    Else {
        Write-Host "[INFO] Scan name: $scan"
    }
    return $scan
}

Function Assert-ArtifactExists($file) {
    If ((Test-Path $file) -eq $false) {
        Write-Host "[ERROR] File does not exist."
        Exit 1
    }
    Else {

        Write-Host "[INFO] File to upload: $file."
    }
}

Function Assert-AppIdExists($app) {
    Write-Host "[INFO] Getting App ID."
    Try {
        [xml]$appIdXml = java -jar $javaWrapper -vid $apiId -vkey $apiKey $proxyInfo -action GetAppList | Select-String -Pattern $app
        $appId = $appIdXml.app.app_id
        Write-Host "[INFO] App ID: $appId"
        return $appId
    }
    Catch {
        Write-Host "[INFO] App ID does not exist."
        return $Null
    }
}

Function New-AppId($app) {
    Write-Host "[INFO] Creating App: $app"
    $result = java -jar $javaWrapper -vid $apiId -vkey $apiKey $proxyInfo -action createApp -appname "$app" -criticality high
    Write-Host "[INFO] App created."
    $appId = Assert-AppIdExists $app
    return $appId
}

Function Start-VeracodeScanNoWait($app, $sandbox, $file, $scan) {
    Write-Host "[INFO] Upload and start scan."
    If (-not ([string]::IsNullOrEmpty($sandbox))) {
        $result = java -jar $javaWrapper -vid $apiId -vkey $apiKey $proxyInfo -action uploadandscan -appname $app -createprofile false -sandboxname $sandbox -createsandbox true -filepath "$file" -version "$scan" > $outputFileName
    } else {
        $result = java -jar $javaWrapper -vid $apiId -vkey $apiKey $proxyInfo -action uploadandscan -appname $app -createprofile false -filepath "$file" -version "$scan" > $outputFileName
    }
    Write-Host ""
    $uploadResult = Get-Content -raw $outputFileName
    If ($uploadResult -like "*Starting pre-scan*") {
        Write-Host ""
        Write-Host "[INFO] File uploaded and Pre-scan started."
        return $True
    }
    Else {
        Write-Host ""
        Write-Host "[ERROR] Error with upload or scan submission: $uploadResult"
        return $False
    }
}

Function main()
{
	$scan = Get-ScanName $scan
    Assert-ArtifactExists $file
    If ((Assert-AppIdExists $app) -eq $Null) {
        New-AppId $app
    }
    $didScanStart = Start-VeracodeScanNoWait $app $sandbox $file $scan
    If ($didScanStart -eq $False) {
        Exit 1
    }
    Else {
        Exit 0
    }
}

main
