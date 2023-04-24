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
      $Target = Resolve-Target $Namespace $Name
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
  [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Credential')]
  param(
    #The credential that you want to store.
    [Parameter(Position = 0, Mandatory, ValueFromPipeline)][PSCredential]$Credential,
    #The name of the secret that you wish to set
    [Parameter(Position = 1, ParameterSetName = 'Credential')][ValidateNotNullOrEmpty()][string]$Name,
    #The namespace for the name of the credential you wish to use. Defaults to "powershell"
    [Parameter(ParameterSetName = 'Credential')][ValidateNotNullOrEmpty()][string]$Namespace = $DefaultNamespace,
    #The target you wish to set. If not specified, uses powershell:username as the target
    [Parameter(ParameterSetName = 'Target')][ValidateNotNullOrEmpty()][string]$Target,
    #Allow overwrite of existing credentials
    [Switch]$AllowClobber
  )
  process {
    if ($Name) {
      $Target = Resolve-Target $Namespace $Name
    }
    if (-not $Target) {
      $Target = Resolve-Target $Namespace $Credential.UserName
    }
    if (-not $PSCmdlet.ShouldProcess($Target, "Save Credential [Username $($Credential.UserName)]")) { return }

    if ((Get-WinCredential -Target $Target) -and -not $AllowClobber) {
      Write-Error "Credential for target '$Target' already exists. Use -AllowClobber to overwrite."
      return
    }

    $result = [CredentialManager]::SaveCredentials($Target, $Credential.GetNetworkCredential(), [CredentialType]::Generic, $true)
    if (-not $result) {
      Write-Error "Failed to save credential for target '$Target'"
      return
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
    Removes a credential from the Windows Credential Manager. For safety, you must explicitly specify the name of the credential, you cannot pass a credential because the username may accidentally match something you didn't intend.
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
    [Parameter(Mandatory, ParameterSetName = 'Target')][ValidateNotNullOrEmpty()][string]$Target
  )
  process {
    if ($Name) {
      $Target = Resolve-Target $Namespace $Name
    }
    if (-not $PSCmdlet.ShouldProcess($Target, "Remove Credential [Username $($Credential.UserName)]")) { return }

    try {
      [bool]$result = [CredentialManager]::RemoveCredentials($Target, [CredentialType]::Generic)
      if (-not $result) {
        Write-Error "Failed to remove credential for target '$Target'"
        return
      }
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
    Write-Verbose "Removed Windows Credential with Target: $target"
  }
}

function Resolve-Target ([ValidateNotNullOrEmpty()][string]$Namespace, [ValidateNotNullOrEmpty()][string]$Name) {
  $Namespace, $Name -join '/'
}

