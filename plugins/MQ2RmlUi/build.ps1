param(
    [string]$MQRoot = "",
    [switch]$NoDeploy
)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$build = Join-Path $here "build"

if (-not $env:VCPKG_ROOT) {
    throw "Set VCPKG_ROOT to your vcpkg install (RmlUi via x86-windows-static)."
}

cmake -S $here -B $build -G "Visual Studio 17 2022" -A Win32 `
    -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
    -DVCPKG_TARGET_TRIPLET=x86-windows-static
if ($LASTEXITCODE -ne 0) { throw "configure failed" }

cmake --build $build --config Release
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$dll = Join-Path $build "Release\MQ2RmlUi.dll"
Write-Host "Built $dll"

if (-not $NoDeploy) {
    if (-not $MQRoot) { throw "Pass -MQRoot <MacroQuest root> to deploy, or use -NoDeploy." }
    $target = Join-Path $MQRoot "plugins\MQ2RmlUi.dll"
    try {
        Copy-Item $dll $target -Force
        Write-Host "Deployed to $target"
    } catch {
        $staged = "$target.new"
        Copy-Item $dll $staged -Force
        Write-Warning "MQ2RmlUi.dll is in use. Staged as $staged — unload plugin, then rename."
    }
}
