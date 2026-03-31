$ErrorActionPreference = 'Stop'

$packageName = 'gh-audit'

Uninstall-ChocolateyZipPackage `
  -PackageName $packageName `
  -ZipFileName "gh-audit-windows-amd64.zip"
