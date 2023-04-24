using namespace AdysTech.CredentialManager
using namespace System.ComponentModel

$debugBinPath = Join-Path $PSScriptRoot 'bin/Debug/netstandard2.0/publish'
if (Test-Path $debugBinPath) {
  Write-Warning "Debug build detected. Using assemblies at $debugBinPath"
  Add-Type -Path $debugBinPath/*.dll
} else {
  Add-Type -Path $PSScriptRoot/*.dll
}

$ErrorActionPreference = 'Stop'
$SCRIPT:DefaultNamespace = 'powershell'

function Get-WinCredential {
  <#
  .SYNOPSIS
    Fetches a credential from the Windows Credential Manager. If you do not specify a name or target, it will fetch all credentials by default.
  #>
  [CmdletBinding(DefaultParameterSetName = 'Name')]
  [OutputType([PSCredential])]
  [OutputType([AdysTech.CredentialManager.ICredential])]
  param(
    #The name of the secret that you wish to fetch
    [Parameter(Position = 0, ParameterSetName = 'Name')][ValidateNotNullOrEmpty()][string]$Name,
    #The namespace for the name of the credential you wish to use. Defaults to "powershell"
    [Parameter(ParameterSetName = 'Name')][ValidateNotNullOrEmpty()][string]$Namespace = $DefaultNamespace,
    #The target you wish to fetch. Supports "Like" wildcard syntax
    [Parameter(ParameterSetName = 'Target', ValueFromPipeline)][ValidateNotNullOrEmpty()][string]$Target,
    #Retrieve the raw credential object. NOTE: May expose secrets as plaintext!
    [Switch]$Raw,
    #Retrieve all Windows Credentials, not just the ones in the powershell namespace
    [Switch]$All
  )
  process {
    if ($Name) {
      $Target = Resolve-Target
    }
    #NOTE: Null will return nothing vs. the absence of a parameter which returns everything
    [ICredential[]]$credentials = if ($Target) {
      [CredentialManager]::EnumerateICredentials($Target)
    } else {
      $allCredentials = [CredentialManager]::EnumerateICredentials()
      if ($all) {
        $allCredentials
      } else {
        $allCredentials | Where-Object { $PSItem.TargetName.StartsWith($DefaultNamespace) }
      }
    }

    foreach ($cred in $credentials) {
      if ($Raw) {
        $cred
      } else {
        $cred | ConvertFrom-WinICredential
      }
    }
  }
}

function Save-WinCredential {
  <#
  .SYNOPSIS
    Sets a credential in the Windows Credential Manager.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    #The credential that you want to store.
    [Parameter(Position = 0, Mandatory, ValueFromPipeline)][PSCredential]$Credential,
    #The name of the secret that you wish to set
    [Parameter(Mandatory, ParameterSetName = 'Name')][ValidateNotNullOrEmpty()][string]$Name,
    #The namespace for the name of the credential you wish to use. Defaults to "powershell"
    [Parameter(ParameterSetName = 'Name')][ValidateNotNullOrEmpty()][string]$Namespace = $DefaultNamespace,
    #The target you wish to set. If not specified, uses powershell:username as the target
    [Parameter(ParameterSetName = 'Target')][ValidateNotNullOrEmpty()][string]$Target
  )
  process {
    if ($Name) {
      $Target = Resolve-Target $Namespace $Name
    }
    if (-not $Target) {
      $Target = Resolve-Target $Namespace $Credential.UserName
    }
    if (-not $PSCmdlet.ShouldProcess($Target, "Save Credential [Username $($Credential.UserName)]")) { return }

    $result = [CredentialManager]::SaveCredentials($Target, $Credential.GetNetworkCredential(), [CredentialType]::Generic, $true)
    if (-not $result) {
      $PSCmdlet.WriteError("Failed to save credential for target '$Target'")
    }
    Write-Verbose "Created Windows Credential with Target Name: $($result.TargetName)"
  }
}

function ConvertFrom-WinICredential {
  <#
  .SYNOPSIS
    Converts an ICredential object to a PSCredential object.
  #>
  [CmdletBinding()]
  [OutputType([PSCredential])]
  [OutputType([AdysTech.CredentialManager.ICredential])]
  param(
    #The ICredential object to convert
    [Parameter(Mandatory, ValueFromPipeline)][ValidateNotNullOrEmpty()][AdysTech.CredentialManager.ICredential]$ICredential
  )
  process {
    $netCred = $ICredential.ToNetworkCredential()
    $Username = if ($netCred.UserName) { $netCred.UserName } else { '**UNSPECIFIED**' }
    [PSCredential]::new($Username, $netCred.SecurePassword)
  }
}

function Remove-WinCredential {
  <#
  .SYNOPSIS
    Removes a credential from the Windows Credential Manager.
  #>
  [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Name', ConfirmImpact = 'High')]
  [OutputType([PSCredential])]
  [OutputType([AdysTech.CredentialManager.ICredential])]
  param(
    #The name of the secret that you wish to remove
    [Parameter(Mandatory, Position = 0, ParameterSetName = 'Name')][ValidateNotNullOrEmpty()][string]$Name,
    #The namespace for the name of the credential you wish to use. Defaults to "powershell"
    [Parameter(ParameterSetName = 'Name')][ValidateNotNullOrEmpty()][string]$Namespace = $DefaultNamespace,
    #The target you wish to remove. Supports "Like" wildcard syntax
    [Parameter(Mandatory, ParameterSetName = 'Target')][ValidateNotNullOrEmpty()][string]$Target,
    #Allow overwrite of existing credentials
    [Switch]$AllowClobber
  )
  process {
    if ($Name) {
      $Target = Resolve-Target $Namespace $Name
    }
    if (-not $PSCmdlet.ShouldProcess($Target, "Remove Credential [Username $($Credential.UserName)]")) { return }

    try {
      $result = [CredentialManager]::RemoveCredentials($Target, [CredentialType]::Generic)
    } catch {
      $innerException = $PSItem.Exception.InnerException
      $APIErrorCode = $innerException.ErrorCode
      $APIErrorMessage = ([Win32Exception]$apiErrorCode).Message
      $PSItem.ErrorDetails = switch ($APIErrorMessage) {
        'Element not found.' {
          "The credential '$target' does not exist or could not be deleted."
        }
        default {
          "Failed to remove credential for target '$Target': $($InnerException.Message): $APIErrorMessage"
        }
      }
      $PSCmdlet.ThrowTerminatingError($PSItem)
    }
    if (-not $result) {
      $PSCmdlet.WriteError("Failed to remove credential for target '$Target'")
      return
    }
    Write-Verbose "Removed Windows Credential with Target Name: $($result.TargetName)"
  }
}

function Resolve-Target ([ValidateNotNullOrEmpty()][string]$Namespace, [ValidateNotNullOrEmpty()][string]$Name) {
  $Namespace, $Name -join '/'
}

