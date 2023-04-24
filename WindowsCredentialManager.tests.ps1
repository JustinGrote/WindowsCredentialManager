using namespace AdysTech.CredentialManager

#TODO: Test Debug if newer than Release
BeforeAll {
  Import-Module $PSScriptRoot/WindowsCredentialManager.psm1 -Force
}

Describe 'Get-WinCredential' {
  BeforeAll {
    $cred1 = & cmdkey /generic:powershell/pester /user:pesteruser /pass:pesterpw
    $cred2 = & cmdkey /generic:powershell/pester2 /user:pesteruser2 /pass:pesterpw2
    $cred3 = & cmdkey /generic:customnamespace/pester /user:pestercustom /pass:pesterpw
    $cred1, $cred2, $cred3 | ForEach-Object {
      if ($PSItem -notmatch 'Credential added') { throw 'Failed to create test credential' }
    }
  }

  AfterAll {
    cmdkey /delete:powershell/pester
    cmdkey /delete:powershell/pester2
  }

  It 'Fetches all credentials by default' {
    $actual = Get-WinCredential
    $actual.username | Should -Contain 'pesteruser'
    $actual.username | Should -Contain 'pesteruser2'
  }
  It 'Fetches specific credential by Name' {
    $actual = Get-WinCredential -Name pester
    $actual.username | Should -Be 'pesteruser'
  }
  It 'Fetches specific credential by Target' {
    $actual = Get-WinCredential -Target 'customnamespace/pester'
    $actual.username | Should -Be 'pestercustom'
  }
  It 'Fetches raw credentials' {
    $actual = Get-WinCredential -Raw
    $actual[0] | Should -BeOfType [AdysTech.CredentialManager.ICredential]
  }
}

Describe 'Save-WinCredential' {
  BeforeEach {
    cmdkey /delete:powershell/pester | Out-Null
  }
  AfterEach {
    cmdkey /delete:powershell/pester | Out-Null
    cmdkey /delete:powershell/pester2 | Out-Null
  }

  It 'Saves a new PSCredential' {
    $cred = [PSCredential]::new('pester', ('pesterpw' | ConvertTo-SecureString -AsPlainText -Force))
    Save-WinCredential $cred
    $actual = Get-WinCredential -Name 'pester'
    $actual | Should -Not -BeNullOrEmpty
    $actual.username | Should -Be 'pester'
  }

  It 'Saves a new PSCredential with a different name' {
    $cred = [PSCredential]::new('pester', ('pesterpw' | ConvertTo-SecureString -AsPlainText -Force))
    Save-WinCredential -Credential $cred -Name 'pester2'
    $actual = Get-WinCredential -Name 'pester2'
    $actual | Should -Not -BeNullOrEmpty
    $actual.username | Should -Be 'pester'
  }

  It 'Saves a new PS Credential passed via the pipeline' {
    $cred = [PSCredential]::new('pester', ('pesterpw' | ConvertTo-SecureString -AsPlainText -Force))
    $cred | Save-WinCredential
    $actual = Get-WinCredential -Name 'pester'
    $actual | Should -Not -BeNullOrEmpty
    $actual.username | Should -Be 'pester'
  }

  It 'Errors if Credential already exists' {
    & cmdkey /generic:powershell/pester /user:pesteruser /pass:pesterpw

    {
      $cred = [PSCredential]::new('pester', ('pesterpw' | ConvertTo-SecureString -AsPlainText -Force))
      Save-WinCredential $cred -ErrorAction Stop
    } | Should -Throw -ExpectedMessage 'Credential for target ''powershell/pester'' already exists. Use -AllowClobber to overwrite.'
  }
  It 'Deletes existing credential if AllowClobber is specified' {
    & cmdkey /generic:powershell/pester /user:pesteruser /pass:pesterpw

    $cred = [PSCredential]::new('pester', ('newpesterpw' | ConvertTo-SecureString -AsPlainText -Force))
    $result = Save-WinCredential $cred -ErrorAction Stop -AllowClobber -Verbose *>&1
    (Get-WinCredential -Target 'powershell/pester').GetNetworkCredential().Password | Should -Be 'newpesterpw'
  }
}

Describe 'Remove-WinCredential' {
  BeforeEach {
    & cmdkey /generic:powershell/pester /user:pesteruser /pass:pesterpw
  }
  It 'Removes a credential' {
    #Check for a verbose message saying it worked
    Remove-WinCredential -Name pester -Confirm:$false -Verbose 4>&1 | Select-Object -Last 1 | Should -Be 'Removed Windows Credential With Target: powershell/pester'
    Get-WinCredential -Target powershell/pester | Should -BeNullOrEmpty
  }
  It 'Removes a credential in a custom namespace' {
    Remove-WinCredential -Name pester -Namespace customnamespace -Confirm:$false -Verbose 4>&1 | Select-Object -Last 1 | Should -Be 'Removed Windows Credential With Target: customnamespace/pester'
    Get-WinCredential -Target customnamespace/pester | Should -BeNullOrEmpty
  }
  It 'Removes a credential in a custom namespace' {
    Remove-WinCredential -Name pester -Namespace customnamespace -Confirm:$false -Verbose 4>&1 | Select-Object -Last 1 | Should -Be 'Removed Windows Credential With Target: customnamespace/pester'
    Get-WinCredential -Target customnamespace/pester | Should -BeNullOrEmpty
  }
}
