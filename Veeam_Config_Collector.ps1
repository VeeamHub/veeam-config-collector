<#
.SYNOPSIS
# VBR Configuration Collector

.DESCRIPTION
# Auto-discovers latest Swagger version and collects VBR configuration data via REST API.
# Excludes sensitive endpoints (credentials, passwords, user data) for security.

.NOTES
Version: 1.0.4
#>

# Script Constants
# Configuration constants for easy maintenance
$DEFAULT_VBR_PORT = 9419
$API_TIMEOUT_SECONDS = 30
$REQUEST_DELAY_MS = 100
$MAX_RETRIES = 2
$RETRY_BASE_DELAY_SECONDS = 2
$JSON_EXPORT_DEPTH = 20
$MASKING_DIGIT_PADDING = 4
#endregion

# VBR Server Configuration - Interactive Input
Write-Host "VBR Server Configuration" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
$VBRServer = Read-Host "Enter VBR server address (IP or hostname)"
$VBRPortInput = Read-Host "Enter VBR port [$DEFAULT_VBR_PORT]"

# Use default port if nothing entered
if ([string]::IsNullOrWhiteSpace($VBRPortInput)) {
    $VBRPort = $DEFAULT_VBR_PORT
} else {
    $VBRPort = [int]$VBRPortInput
}

Write-Host ""

# Prompt for credentials securely
Write-Host "VBR Credentials Required" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
$Username = Read-Host "Enter VBR username"
$SecurePassword = Read-Host "Enter VBR password" -AsSecureString

# Convert SecureString to plain text for API calls
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)  # Clean up memory

# Format-Json function to optimize JSON output with 2-space indentation
function Format-Json {
    param([Parameter(Mandatory, ValueFromPipeline)][String] $Json)
    $indent = 0
    ($Json -split '\n' | ForEach-Object {
        if ($_ -match '[\]\}]') { $indent-- }
        $line = (' ' * $indent * 2) + $_.TrimStart() -replace '":\s+([[{])', '": $1'
        if ($_ -match '[\[\{]') { $indent++ }
        $line
    }) -join "`n"
}

# Global mapping table for masking
$global:maskingMap = @{}
$global:maskingCounter = 0

# Function to get masked value with sequential index
function Get-MaskedValue {
    param(
        [string]$originalValue,
        [string]$fieldName
    )
    
    if ([string]::IsNullOrWhiteSpace($originalValue)) {
        return $originalValue
    }
    
    # Check if we already masked this value
    $key = "$fieldName|$originalValue"
    if ($global:maskingMap.ContainsKey($key)) {
        return $global:maskingMap[$key]
    }
    
    # Create new masked value with sequential index using configured padding
    $global:maskingCounter++
    $maskedValue = "masked-$fieldName-{0:D$MASKING_DIGIT_PADDING}" -f $global:maskingCounter
    
    # Store in mapping table
    $global:maskingMap[$key] = $maskedValue
    
    return $maskedValue
}

# Recursive function to mask sensitive fields in the data structure
function Invoke-DataMasking {
    param(
        [Parameter(Mandatory)]$InputObject,
        [hashtable]$MaskingRulesCache = @{},
        [string]$CurrentContext = ""
    )
    
    if ($null -eq $InputObject) {
        return $InputObject
    }
    
    # Return primitive types immediately (string, int, bool, etc.)
    if ($InputObject -is [string] -or $InputObject -is [int] -or $InputObject -is [long] -or 
        $InputObject -is [double] -or $InputObject -is [bool] -or $InputObject -is [decimal] -or
        $InputObject -is [byte] -or $InputObject -is [datetime]) {
        return $InputObject
    }
    
    # Helper function to check if field should be masked in current context
    # Uses cached lookup table for O(1) performance instead of O(n) loop
    function Test-MaskField {
        param([string]$FieldName, [string]$Context, [hashtable]$RulesCache)
        
        # Fast lookup: check if this field has any rules
        if (-not $RulesCache.ContainsKey($FieldName)) {
            return $null
        }
        
        # Only loop through rules for this specific field (much smaller subset)
        foreach ($rule in $RulesCache[$FieldName]) {
            # Check if context matches
            if ($rule.Context -eq "*") {
                return $rule.MaskAs
            }
            # Check for exact match
            elseif ($Context -eq $rule.Context) {
                return $rule.MaskAs
            }
            # Check if context ends with the rule context (e.g., "Endpoints.serverInfo" ends with "serverInfo")
            elseif ($Context -like "*.$($rule.Context)" -or $Context -like "*$($rule.Context)") {
                return $rule.MaskAs
            }
        }
        return $null
    }
    
    # Handle different object types
    if ($InputObject -is [System.Collections.IDictionary]) {
        # Process hashtable/dictionary
        $masked = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $value = $InputObject[$key]
            
            # Check if this field should be masked
            $maskAs = Test-MaskField -FieldName $key -Context $CurrentContext -RulesCache $MaskingRulesCache
            
            if ($maskAs -and $value -is [string]) {
                # Mask this field
                $masked[$key] = Get-MaskedValue -originalValue $value -fieldName $maskAs
            }
            elseif ($null -eq $value) {
                # Handle null values
                $masked[$key] = $null
            }
            else {
                # Recursively process nested structures with updated context
                $newContext = if ($CurrentContext) { "$CurrentContext.$key" } else { $key }
                $masked[$key] = Invoke-DataMasking -InputObject $value -MaskingRulesCache $MaskingRulesCache -CurrentContext $newContext
            }
        }
        return $masked
    }
    elseif ($InputObject -is [Array]) {
        # Process array
        $masked = @()
        foreach ($item in $InputObject) {
            if ($null -eq $item) {
                $masked += $null
            }
            else {
                # Arrays don't change context, pass through current context
                $masked += Invoke-DataMasking -InputObject $item -MaskingRulesCache $MaskingRulesCache -CurrentContext $CurrentContext
            }
        }
        return $masked
    }
    elseif ($InputObject -is [PSCustomObject]) {
        # Process PSCustomObject
        $masked = [PSCustomObject]@{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $value = $prop.Value
            
            # Check if this property should be masked
            $maskAs = Test-MaskField -FieldName $prop.Name -Context $CurrentContext -RulesCache $MaskingRulesCache
            
            if ($maskAs -and $value -is [string]) {
                # Mask this property
                $masked | Add-Member -NotePropertyName $prop.Name -NotePropertyValue (Get-MaskedValue -originalValue $value -fieldName $maskAs)
            }
            elseif ($null -eq $value) {
                # Handle null values
                $masked | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $null
            }
            else {
                # Recursively process nested structures with updated context
                $newContext = if ($CurrentContext) { "$CurrentContext.$($prop.Name)" } else { $prop.Name }
                $masked | Add-Member -NotePropertyName $prop.Name -NotePropertyValue (Invoke-DataMasking -InputObject $value -MaskingRulesCache $MaskingRulesCache -CurrentContext $newContext)
            }
        }
        return $masked
    }
    else {
        # Return any other types as-is (enums, etc.)
        return $InputObject
    }
}

# Masking rules configuration (scalable, context-aware)
# Format: @{ Context = "parent.path"; Field = "fieldName"; MaskAs = "maskPrefix" }
$maskingRules = @(
    @{ Context = "*"; Field = "hostName"; MaskAs = "hostName" }                                        # Mask hostName everywhere
    @{ Context = "serverInfo"; Field = "name"; MaskAs = "serverName" }                                 # Mask name in serverInfo
    @{ Context = "workload"; Field = "name"; MaskAs = "workloadName" }                                 # Mask name in workload (license context)
    @{ Context = "license_instances.data"; Field = "name"; MaskAs = "instanceName" }                   # Mask name in license instances
    @{ Context = "sessions.data"; Field = "name"; MaskAs = "sessionName" }                             # Mask name in sessions
    @{ Context = "sessions.data"; Field = "initiatedBy"; MaskAs = "sessionsInitiatedByUser" }          # Mask initiatedBy in sessions
    @{ Context = "sessions.data.result"; Field = "message"; MaskAs = "sessionsMessage" }               # Mask message in sessions
    @{ Context = "taskSessions.data"; Field = "name"; MaskAs = "taskSessionName" }                     # Mask name in taskSessions
    @{ Context = "backupInfrastructure_managedServers.data"; Field = "name"; MaskAs = "managedServerName" } # Mask name in managed servers
    @{ Context = "jobs.data"; Field = "name"; MaskAs = "jobName" }                                     # Mask name in jobs
    @{ Context = "jobs.data"; Field = "description"; MaskAs = "jobsDescription" }                      # Mask description in jobs
    @{ Context = "jobs_states.data"; Field = "name"; MaskAs = "jobStateName" }                         # Mask name in jobs_states
    @{ Context = "backups.data"; Field = "name"; MaskAs = "backupsName" }
    @{ Context = "backupObjects.data"; Field = "name"; MaskAs = "backupObjName" }
    @{ Context = "restorePoints.data"; Field = "name"; MaskAs = "restorePointsName" }
    @{ Context = "agents_protectedComputers.data"; Field = "name"; MaskAs = "protectedComputersName" }
    @{ Context = "authorization_events.data"; Field = "name"; MaskAs = "authorizationeventsName" }
    @{ Context = "agents_protectionGroups.data"; Field = "name"; MaskAs = "protectionGroupsName" }
    @{ Context = "securityAnalyzer_lastRun"; Field = "initiatedBy"; MaskAs = "SALastRunInitiatedByUser" }
    @{ Context = "backupInfrastructure_repositories.data"; Field = "description"; MaskAs = "repositoriesDescription" }
    @{ Context = "backupInfrastructure_scaleOutRepositories.data"; Field = "description"; MaskAs = "SOBRDescription" }
    @{ Context = "backupInfrastructure_managedServers.data"; Field = "description"; MaskAs = "managedServersDescription" }
    @{ Context = "taskSessions.data"; Field = "message"; MaskAs = "taskSessionsMessage" }
    @{ Context = "security_roles.data"; Field = "description"; MaskAs = "securityRolesDescription" }           # Mask description in security_roles
    # Add more context-specific rules as needed:
    # @{ Context = "credentials"; Field = "userName"; MaskAs = "userName" }
    # @{ Context = "repositories"; Field = "path"; MaskAs = "repoPath" }
)

# Build masking rules cache for O(1) lookup performance
# This significantly speeds up masking by indexing rules by field name
$maskingRulesByField = @{}
foreach ($rule in $maskingRules) {
    if (-not $maskingRulesByField.ContainsKey($rule.Field)) {
        $maskingRulesByField[$rule.Field] = @()
    }
    $maskingRulesByField[$rule.Field] += $rule
}

# Ignore self-signed certificate errors
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
    $certCallback = @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback
        {
            public static void Ignore()
            {
                if(ServicePointManager.ServerCertificateValidationCallback == null)
                {
                    ServicePointManager.ServerCertificateValidationCallback += 
                        delegate
                        (
                            Object obj, 
                            X509Certificate certificate, 
                            X509Chain chain, 
                            SslPolicyErrors errors
                        )
                        {
                            return true;
                        };
                }
            }
        }
"@
    Add-Type $certCallback
}
[ServerCertificateValidationCallback]::Ignore()

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "========================================" -ForegroundColor Green
Write-Host "VBR Configuration Collector Script" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Prompt for output file location
$defaultPath = [Environment]::GetFolderPath("Desktop")
Write-Host "Default output location: $defaultPath" -ForegroundColor Cyan
$changeLocation = Read-Host "Do you want to change the output location? (Y/N) [N]"

if ($changeLocation -eq "Y" -or $changeLocation -eq "y") {
    $customPath = Read-Host "Enter the full path for output files"
    
    if (Test-Path -Path $customPath -PathType Container) {
        $outputPath = $customPath
        Write-Host "Output location set to: $outputPath" -ForegroundColor Green
    }
    else {
        Write-Host "Invalid path. Using default Desktop location." -ForegroundColor Yellow
        $outputPath = $defaultPath
    }
}
else {
    $outputPath = $defaultPath
}

Write-Host ""

# Prompt for data masking
Write-Host "Data Masking Configuration" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host "Data masking replaces sensitive information with anonymized values." -ForegroundColor Gray
Write-Host "This protects customer privacy when sharing configuration data." -ForegroundColor Gray
Write-Host "A mapping file will be created to reverse the masking if needed." -ForegroundColor Gray
Write-Host ""
$enableMasking = Read-Host "Enable data masking? (Y/N) [Y]"

if ($enableMasking -eq "N" -or $enableMasking -eq "n") {
    $maskingEnabled = $false
    Write-Host ""
    Write-Host "WARNING: Data masking is DISABLED!" -ForegroundColor Red
    Write-Host "The output will contain sensitive information (hostnames, names, etc.)" -ForegroundColor Yellow
    Write-Host "Only disable masking if you understand the security implications." -ForegroundColor Yellow
    Write-Host ""
}
else {
    $maskingEnabled = $true
    Write-Host "Data masking enabled" -ForegroundColor Green
}

Write-Host ""

# Step 1: Discover the latest Swagger version
Write-Host "Step 1: Discovering latest Swagger API version..." -ForegroundColor Cyan

# Version patterns from the screenshot
$versionPatterns = @(
    "v1.3-rev1",
    "v1.3-rev0",
    "v1.2-rev1",
    "v1.2-rev0",
    "v1.1-rev2",
    "v1.1-rev1",
    "v1.1-rev0",
    "v1-rev2",
    "v1-rev1"
)

# Sensitive endpoints to exclude from collection (security best practice)
$excludedEndpoints = @(
    "/api/v1/credentials",
    "/api/v1/encryptionPasswords",
    "/api/v1/security/users",
    "/api/v1/serverCertificate"
)

# Convert to HashSet for O(1) lookup performance (4x faster than array loop)
$excludedEndpointsSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$excludedEndpoints)

$discoveredVersion = $null
$swaggerJson = $null

foreach ($version in $versionPatterns) {
    $swaggerUrl = "https://${VBRServer}:${VBRPort}/swagger/${version}/swagger.json"
    
    try {
        $response = Invoke-WebRequest -Uri $swaggerUrl -Method Get -ErrorAction Stop -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            $swaggerJson = $response.Content | ConvertFrom-Json
            $discoveredVersion = $version
            Write-Host "SUCCESS! Found Swagger version: $version" -ForegroundColor Green
            break
        }
    }
    catch {
        # Silently continue to next version
    }
}

if (-not $discoveredVersion) {
    Write-Host "ERROR: Could not discover any Swagger API version!" -ForegroundColor Red
    Write-Host "Please verify:" -ForegroundColor Yellow
    Write-Host "  - Server address: $VBRServer" -ForegroundColor Yellow
    Write-Host "  - Port: $VBRPort" -ForegroundColor Yellow
    Write-Host "  - Network connectivity" -ForegroundColor Yellow
    Write-Host "  - VBR REST API service is running" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Step 2: Authenticate
Write-Host "Step 2: Authenticating to VBR server..." -ForegroundColor Cyan

$tokenUrl = "https://${VBRServer}:${VBRPort}/api/oauth2/token"

# Use hashtable format like the working script
$body = @{
    grant_type = "password"
    username = $Username
    password = $Password
}

# Convert discovered Swagger version to API version format
# Swagger uses format like "v1.2-rev1" or "V1.2-REV1"
# API calls need format like "1.2-rev1" (lowercase, no 'v' prefix)
$apiVersion = $discoveredVersion -replace '^v', '' -replace '^V', ''
$apiVersion = $apiVersion.ToLower()

# Try with x-api-version header (like the working script)
$headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
    "x-api-version" = $apiVersion
}

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -Headers $headers
    $token = $tokenResponse.access_token
    
    # Clear plaintext credentials from memory immediately
    $Password = $null
    $body = $null
    $tokenResponse = $null
    
    Write-Host "Authentication successful!" -ForegroundColor Green
}
catch {
    Write-Host "Authentication failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)" -ForegroundColor Red
    
    # Try to get more details from the response
    if ($_.Exception.Response) {
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            Write-Host "Response Body: $responseBody" -ForegroundColor Red
        }
        catch {
            # Ignore if we can't read the response
        }
    }
    
    Write-Host "`nNote: The working script uses these same credentials successfully." -ForegroundColor Yellow
    Write-Host "Please verify the server, username, and password in the script." -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Step 3: Parse Swagger and extract parameter-free GET endpoints
Write-Host "Step 3: Parsing Swagger definition..." -ForegroundColor Cyan

$getEndpoints = @()
$totalEndpoints = 0
$parameterFreeEndpoints = 0

foreach ($path in $swaggerJson.paths.PSObject.Properties) {
    $pathName = $path.Name
    $pathData = $path.Value
    
    # Check if this path has a GET method
    if ($pathData.PSObject.Properties.Name -contains "get") {
        $totalEndpoints++
        $getMethod = $pathData.get
        
        # Check if path contains parameters (like {id})
        $hasPathParams = $pathName -match '\{[^}]+\}'
        
        # Check if there are required query parameters
        $hasRequiredParams = $false
        if ($getMethod.parameters) {
            foreach ($param in $getMethod.parameters) {
                if ($param.required -eq $true -and $param.in -ne "header") {
                    $hasRequiredParams = $true
                    break
                }
            }
        }
        
        # Only include endpoints without required parameters
        if (-not $hasPathParams -and -not $hasRequiredParams) {
            $parameterFreeEndpoints++
            $getEndpoints += @{
                Path = $pathName
                Summary = $getMethod.summary
                Description = $getMethod.description
                OperationId = $getMethod.operationId
            }
        #   Write-Host "  Found: $pathName" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "Total GET endpoints found: $totalEndpoints" -ForegroundColor Yellow
Write-Host "Parameter-free GET endpoints: $parameterFreeEndpoints" -ForegroundColor Green
Write-Host ""

# Step 4: Execute all parameter-free GET endpoints
Write-Host "Step 4: Collecting data from all endpoints..." -ForegroundColor Cyan
Write-Host ""

$results = [ordered]@{
    ExportMetadata = [ordered]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ProductVersion = "N/A"  # Will be filled after serverInfo call
        APIVersion = $apiVersion
        TotalEndpoints = $parameterFreeEndpoints
        SuccessfulRequests = 0
        FailedRequests = 0
        ExcludedForSecurity = 0
    }
    Endpoints = [ordered]@{}
    Errors = @()
}

$headers = @{
    "Authorization" = "Bearer $token"
    "x-api-version" = $apiVersion
    "Accept" = "application/json"
}

$counter = 0
foreach ($endpoint in $getEndpoints) {
    $counter++
    $path = $endpoint.Path
    $url = "https://${VBRServer}:${VBRPort}${path}"
    
    # Create a friendly name from the path (remove /api/v1/ and use last segment)
    $friendlyName = $path -replace '^/api/v\d+(\.\d+)?/', '' -replace '/', '_'
    if ([string]::IsNullOrEmpty($friendlyName)) {
        $friendlyName = "root"
    }
    
    # Check if endpoint should be excluded for security (O(1) HashSet lookup)
    if ($excludedEndpointsSet.Contains($path)) {
        Write-Host "[$counter/$parameterFreeEndpoints] SKIPPED: $friendlyName (Sensitive data - excluded for security)" -ForegroundColor Yellow
        $results.ExportMetadata.ExcludedForSecurity++
        continue
    }
    
    Write-Host "[$counter/$parameterFreeEndpoints] Querying: $path" -ForegroundColor Cyan
    
    $requestSucceeded = $false
    $lastError = $null
    $lastStatusCode = $null
    
    for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
        try {
            $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -TimeoutSec $API_TIMEOUT_SECONDS -ErrorAction Stop
            
            # Determine record count
            $recordCount = 0
            if ($response -is [Array]) {
                $recordCount = $response.Count
            }
            elseif ($response.data -and $response.data -is [Array]) {
                $recordCount = $response.data.Count
            }
            elseif ($response.pagination -and $response.pagination.total) {
                $recordCount = $response.pagination.total
            }
            else {
                $recordCount = 1
            }
            
            # Store the raw API response directly (no wrapper)
            $results.Endpoints[$friendlyName] = $response
            
            $results.ExportMetadata.SuccessfulRequests++
            $requestSucceeded = $true
            
            if ($attempt -gt 1) {
                Write-Host "  Success ($recordCount records) [retry $($attempt - 1) succeeded]" -ForegroundColor Green
            }
            else {
                Write-Host "  Success ($recordCount records)" -ForegroundColor Green
            }
            
            # If this is serverInfo, capture the version
            if ($path -eq "/api/v1/serverInfo" -and $response.buildVersion) {
                $results.ExportMetadata.ProductVersion = $response.buildVersion
            }
            
            break  # Exit retry loop on success
        }
        catch {
            $lastError = $_.Exception.Message
            $lastStatusCode = $_.Exception.Response.StatusCode.value__
            
            # Determine if this is a retryable error (transient failures)
            $isRetryable = ($lastError -match "timed out|timeout") -or
                           ($lastStatusCode -in @(408, 429, 500, 502, 503, 504))
            
            if ($isRetryable -and $attempt -lt $MAX_RETRIES) {
                $delaySeconds = $RETRY_BASE_DELAY_SECONDS * [math]::Pow(2, $attempt - 1)
                Write-Host "  Attempt $attempt failed (Status: $lastStatusCode). Retrying in ${delaySeconds}s..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds $delaySeconds
            }
            else {
                # Non-retryable error or final attempt exhausted — stop retrying
                break
            }
        }
    }
    
    # Record failure if all attempts were exhausted
    if (-not $requestSucceeded) {
        $results.Endpoints[$friendlyName] = [ordered]@{
            Status = "Failed"
            Error = $lastError
            StatusCode = $lastStatusCode
            Path = $path
            Attempts = $attempt
        }
        
        $results.Errors += [ordered]@{
            Endpoint = $path
            FriendlyName = $friendlyName
            Error = $lastError
            StatusCode = $lastStatusCode
            Attempts = $attempt
        }
        
        $results.ExportMetadata.FailedRequests++
        Write-Host "  Failed after $attempt attempt(s): $lastError (Status: $lastStatusCode)" -ForegroundColor Red
    }
    
    # Small delay to avoid overwhelming the server
    Start-Sleep -Milliseconds $REQUEST_DELAY_MS
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Data Collection Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Successful requests: $($results.ExportMetadata.SuccessfulRequests)" -ForegroundColor Green
Write-Host "Failed requests: $($results.ExportMetadata.FailedRequests)" -ForegroundColor Yellow
Write-Host "Excluded for security: $($results.ExportMetadata.ExcludedForSecurity)" -ForegroundColor Cyan
Write-Host ""

# Step 5: Logout and revoke token
Write-Host "Step 5: Logging out and revoking access token..." -ForegroundColor Cyan

$logoutUrl = "https://${VBRServer}:${VBRPort}/api/oauth2/logout"
$logoutHeaders = @{
    "Authorization" = "Bearer $token"
    "x-api-version" = $apiVersion
}

try {
    Invoke-RestMethod -Uri $logoutUrl -Method Post -Headers $logoutHeaders -ErrorAction Stop | Out-Null
    Write-Host "Logout successful - token revoked" -ForegroundColor Green
}
catch {
    Write-Host "Warning: Logout failed, but continuing" -ForegroundColor Yellow
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# Clear token and auth headers from memory after logout
$token = $null
$logoutHeaders = $null
$headers = $null

Write-Host ""

# Step 6: Export results to JSON
Write-Host "Step 6: Exporting results..." -ForegroundColor Cyan

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outputFile = Join-Path -Path $outputPath -ChildPath "CCollectorExport_${timestamp}.json"

# Apply data masking if enabled
if ($maskingEnabled) {
    Write-Host ""
    Write-Host "Applying data masking..." -ForegroundColor Cyan
    Write-Host "  Active masking rules: $($maskingRules.Count)" -ForegroundColor Gray
    
    # Reset masking counters
    $global:maskingMap = @{}
    $global:maskingCounter = 0
    
    # Apply masking with context-aware rules using cached lookup for performance
    $exportResults = Invoke-DataMasking -InputObject $results -MaskingRulesCache $maskingRulesByField -CurrentContext ""
    
    Write-Host "  Masked $($global:maskingMap.Count) unique values" -ForegroundColor Green
    
    # Create mapping file
    $mappingFile = Join-Path -Path $outputPath -ChildPath "CCollectorExport_${timestamp}_mapping.txt"
    
    $mappingContent = @"
Data Masking Map
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
================================

IMPORTANT: Keep this file secure!
This file contains the mapping between masked and original values.
Without this file, you cannot reverse the masking.

Total Masked Values: $($global:maskingMap.Count)

Mappings:
---------

"@
    
    # Add each mapping
    foreach ($entry in $global:maskingMap.GetEnumerator() | Sort-Object Value) {
        $parts = $entry.Key -split '\|'
        $fieldName = $parts[0]
        $originalValue = $parts[1]
        $maskedValue = $entry.Value
        
        $mappingContent += "$maskedValue = $originalValue`r`n"
    }
    
    $mappingContent | Out-File -FilePath $mappingFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "IMPORTANT: Mapping file created!" -ForegroundColor Yellow
    Write-Host "Location: $mappingFile" -ForegroundColor Yellow
    Write-Host "This file allows you to reverse the masking. Keep it secure!" -ForegroundColor Yellow
}
else {
    Write-Host "Masking disabled - exporting original data" -ForegroundColor Gray
    $exportResults = $results
}

Write-Host ""

# Export with optimized formatting (2-space indentation)
$exportResults | ConvertTo-Json -Depth $JSON_EXPORT_DEPTH | Format-Json | Out-File -FilePath $outputFile -Encoding UTF8

Write-Host "Results exported to: $outputFile" -ForegroundColor Green
Write-Host ""

# Display error summary if any
if ($results.Errors.Count -gt 0) {
    Write-Host "Error Summary:" -ForegroundColor Yellow
    Write-Host "==============" -ForegroundColor Yellow
    foreach ($errorItem in $results.Errors) {
        Write-Host "  $($errorItem.FriendlyName) - $($errorItem.Endpoint)" -ForegroundColor Red
        Write-Host "    Error: $($errorItem.Error)" -ForegroundColor DarkRed
        Write-Host "    Status Code: $($errorItem.StatusCode)" -ForegroundColor DarkRed
        Write-Host ""
    }
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "VBR Configuration Collector Script completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Clean up large variables to free memory
$exportResults = $null
$results = $null
$maskingRulesByField = $null
$global:maskingMap = $null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

# Ask if user wants to open the output file location
$openFolder = Read-Host "Do you want to open the output folder? (Y/N) [Default: N]"
if ($openFolder -eq "Y" -or $openFolder -eq "y") {
    Invoke-Item $outputPath
}
