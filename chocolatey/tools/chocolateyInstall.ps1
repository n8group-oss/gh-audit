$ErrorActionPreference = 'Stop'

$packageName = 'gh-audit'
$version = $env:chocolateyPackageVersion
$url = "https://github.com/n8group-oss/gh-audit/releases/download/v${version}/gh-audit-windows-amd64.zip"
$checksum = '__SHA256_HASH__'
$checksumType = 'sha256'

$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

Install-ChocolateyZipPackage `
  -PackageName $packageName `
  -Url64bit $url `
  -Checksum64 $checksum `
  -ChecksumType64 $checksumType `
  -UnzipLocation $toolsDir
