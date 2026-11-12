param(
    [Parameter(Mandatory=$true)][long]$RunId,
    [Parameter(Mandatory=$true)][string]$NotesFile,
    [string]$BuildTools="artifacts/android-build-tools/android-37.0"
)
$ErrorActionPreference="Stop"
Set-Location (Resolve-Path (Join-Path $PSScriptRoot "../.."))
$repo="yuuolo/prism-phone"
$legacyRepo="yuuolo/prism"
$gh="C:/Program Files/GitHub CLI/gh.exe"
$java="C:/Program Files/Java/jdk-24/bin/java.exe"
function Assert-Exit {if($LASTEXITCODE -ne 0) {throw "External command failed ($LASTEXITCODE)"}}
$run=(& $gh run view $RunId --repo $repo --json status,conclusion,headSha,headBranch,workflowName | ConvertFrom-Json); Assert-Exit
if($run.status -ne "completed" -or $run.conclusion -ne "success") {throw "Build and emulator verification must pass before publishing"}
if($run.headBranch -ne "main" -or $run.workflowName -ne "Android") {throw "Only the main branch Android workflow may be published"}
function Get-Release([string]$releaseRepo,[string]$releaseTag) {
    $response=& $gh api "repos/$releaseRepo/releases/tags/$releaseTag" 2>&1
    if($LASTEXITCODE -eq 0) {return (($response -join "`n") | ConvertFrom-Json)}
    if(($response -join "`n") -match 'HTTP 404') {return $null}
    throw "Cannot inspect release $releaseRepo/$releaseTag; refusing to publish"
}
$work="artifacts/android-release-$RunId"
New-Item -ItemType Directory -Force $work | Out-Null
$unsigned=Join-Path $work "app-release-unsigned.apk"
if(-not (Test-Path $unsigned)) {& $gh run download $RunId --repo $repo --name prism-android-unsigned-release --dir $work; Assert-Exit}
$badging=(& (Join-Path $BuildTools "aapt2.exe") dump badging $unsigned) -join "`n"; Assert-Exit
if($badging -notmatch "package: name='dev.prism.android' versionCode='(\d+)' versionName='([0-9A-Za-z.+-]+)'") {throw "Unexpected Android package"}
$code=[long]$Matches[1]; $version=$Matches[2]
if($badging -match "application-debuggable") {throw "Debuggable APKs cannot be released"}
if($badging -notmatch "minSdkVersion:'(\d+)'") {throw "Missing minimum SDK"}
$minimum=[int]$Matches[1]
$tag="android-v$version"; $name="Prism-Android-$version.apk"; $apk=Join-Path $work $name
& $java --enable-native-access=ALL-UNNAMED -jar (Join-Path $BuildTools "lib/apksigner.jar") sign --ks android/.signing/prism-android.jks --ks-key-alias prism-android --ks-pass file:android/.signing/store-password.txt --out $apk $unsigned; Assert-Exit
$certificate=(& $java --enable-native-access=ALL-UNNAMED -jar (Join-Path $BuildTools "lib/apksigner.jar") verify --verbose --print-certs $apk) -join "`n"; Assert-Exit
if($certificate -notmatch 'certificate SHA-256 digest: 618f92202c7e120f365eebc928044ec68422bd12a26ba7337e43075336f6f1c0') {throw "Signing certificate differs from the published Android Alpha"}
& (Join-Path $BuildTools "zipalign.exe") -c -P 16 4 $apk; Assert-Exit
$hash=(Get-FileHash $apk -Algorithm SHA256).Hash.ToLowerInvariant()
function Assert-ChannelVersion([string]$channelRepo) {
$channel=Get-Release $channelRepo 'android-updates'
if($channel -and ($channel.assets | Where-Object {$_.name -eq "android-update.json"})) {
    $previousDir=Join-Path $work ("channel-"+[Guid]::NewGuid().ToString("N"))
    & $gh release download android-updates --repo $channelRepo --pattern android-update.json --dir $previousDir; Assert-Exit
    $previous=Get-Content (Join-Path $previousDir "android-update.json") -Raw | ConvertFrom-Json
    if([long]$previous.versionCode -gt $code -or ([long]$previous.versionCode -eq $code -and $previous.sha256 -ne $hash)) {throw "Refusing to roll back or replace an existing update version"}
}
}
# Validate both channels before changing either release. Old clients only accept old-repo URLs.
Assert-ChannelVersion $repo
Assert-ChannelVersion $legacyRepo
$checksum="$apk.sha256"
[IO.File]::WriteAllText((Join-Path (Get-Location) $checksum),"$hash  $name`n",[Text.Encoding]::ASCII)
function Publish-Apk([string]$releaseRepo,[string]$target,[string]$releaseNotes) {
$existing=Get-Release $releaseRepo $tag
if($existing) {
    $asset=$existing.assets | Where-Object {$_.name -eq $name}
    if(-not $asset -or $asset.digest -ne "sha256:$hash") {throw "Release already exists with different assets; never replace an APK for an existing version"}
} else {
    & $gh release create $tag $apk $checksum --repo $releaseRepo --target $target --title "Prism Android $version" --notes-file $releaseNotes --prerelease --latest=false; Assert-Exit
}
}
Publish-Apk $repo $run.headSha $NotesFile
$legacyTarget=(& $gh api "repos/$legacyRepo/git/ref/heads/master" --jq '.object.sha'); Assert-Exit
$legacyNotes=Join-Path $work "legacy-release-notes.md"
[IO.File]::WriteAllText((Join-Path (Get-Location) $legacyNotes),"Compatibility mirror of https://github.com/$repo/releases/tag/$tag`nSource: https://github.com/$repo/commit/$($run.headSha)`n`n"+(Get-Content $NotesFile -Raw),[Text.UTF8Encoding]::new($false))
Publish-Apk $legacyRepo $legacyTarget $legacyNotes
# The only uploaded files are the signed APK, its hash, and public update metadata.
# Signing keys and passwords remain on this machine.
$metadata=[ordered]@{schemaVersion=1; versionCode=$code; versionName=$version; minSdk=$minimum; size=(Get-Item $apk).Length;
    sha256=$hash; apkUrl="https://github.com/$repo/releases/download/$tag/$name";
    notes=(Get-Content $NotesFile -Raw).Substring(0,[Math]::Min(16000,(Get-Content $NotesFile -Raw).Length)); publishedAt=[DateTime]::UtcNow.ToString("o")}
$manifest=Join-Path $work "android-update.json"
[IO.File]::WriteAllText((Join-Path (Get-Location) $manifest),($metadata | ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
function Publish-Channel([string]$channelRepo,[string]$target,[string]$manifestFile) {
if(-not (Get-Release $channelRepo 'android-updates')) {
    & $gh release create android-updates --repo $channelRepo --target $target --title "Android 更新通道" --notes "仅提供安卓客户端的更新元数据，不改变桌面版更新入口。" --prerelease --latest=false; Assert-Exit
}
& $gh release upload android-updates $manifestFile --repo $channelRepo --clobber; Assert-Exit
}
Publish-Channel $repo $run.headSha $manifest
$metadata.apkUrl="https://github.com/$legacyRepo/releases/download/$tag/$name"
$legacyManifest=Join-Path $work "legacy/android-update.json"
New-Item -ItemType Directory -Force (Split-Path $legacyManifest) | Out-Null
[IO.File]::WriteAllText((Join-Path (Get-Location) $legacyManifest),($metadata | ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
Publish-Channel $legacyRepo $legacyTarget $legacyManifest
& $gh api "repos/$repo/releases/tags/$tag" --jq '.assets[]|{name,digest}'; Assert-Exit
Write-Output "https://github.com/$repo/releases/tag/$tag"
