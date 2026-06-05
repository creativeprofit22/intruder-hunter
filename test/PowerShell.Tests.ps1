$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$PowerShellFiles = @(
    'intruder-hunter.ps1'
    Get-ChildItem -Path (Join-Path $RepoRoot 'lib/windows') -Filter '*.ps1' -File | ForEach-Object {
        Resolve-Path -RelativeBasePath $RepoRoot -Relative $_.FullName
    }
)

Describe 'PowerShell source files' {
    foreach ($relativePath in $PowerShellFiles) {
        It "parses $relativePath" {
            $path = Join-Path $RepoRoot $relativePath
            $tokens = $null
            $parseErrors = $null

            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors) | Out-Null

            $parseErrors | Should -BeNullOrEmpty
        }
    }
}
