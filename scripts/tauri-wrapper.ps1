param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $TauriArgs
)

$ErrorActionPreference = "Stop"

$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if (-not (Test-Path $cargoBin)) {
  throw "Rust cargo bin path not found: $cargoBin"
}

$msvcRootBase = "C:\BuildTools\VC\Tools\MSVC"
$msvcVersion = Get-ChildItem $msvcRootBase -Directory -ErrorAction Stop |
  Sort-Object Name -Descending |
  Select-Object -First 1
if (-not $msvcVersion) {
  throw "MSVC toolset folder not found under $msvcRootBase"
}
$msvcRoot = $msvcVersion.FullName

$sdkLibBase = "C:\Program Files (x86)\Windows Kits\10\Lib"
$sdkIncludeBase = "C:\Program Files (x86)\Windows Kits\10\Include"
$sdkVersion = Get-ChildItem $sdkLibBase -Directory -ErrorAction Stop |
  Sort-Object Name -Descending |
  Select-Object -First 1
if (-not $sdkVersion) {
  throw "Windows SDK lib folder not found under $sdkLibBase"
}
$sdk = $sdkVersion.Name

$env:PATH = "$cargoBin;$msvcRoot\bin\Hostx86\x64;$env:PATH"
$env:LIB = "$msvcRoot\lib\x64;$sdkLibBase\$sdk\ucrt\x64;$sdkLibBase\$sdk\um\x64"
$env:INCLUDE = "$msvcRoot\include;$sdkIncludeBase\$sdk\ucrt;$sdkIncludeBase\$sdk\um;$sdkIncludeBase\$sdk\shared;$sdkIncludeBase\$sdk\winrt;$sdkIncludeBase\$sdk\cppwinrt"

if (-not $TauriArgs -or $TauriArgs.Count -eq 0) {
  $TauriArgs = @("dev")
}

& npm run tauri:raw -- @TauriArgs
exit $LASTEXITCODE
