# Dumping

## Usual

- Unzip the apk
- Find `libil2cpp.so`
  - Usually in `lib/arm64-v8a/`
- Find `global-metadata.dat` using search function within the apk
- Then use Il2CppDumper to dump or any other tools that requires `libil2cpp.so` and `global-metadata.dat`

## Il2CppDumper GUI
- Choose ARMv7 only

## Gameguardian

## Il2cpptool

- Download and Extract the zip file
- Decompile game apk
- Move the libTool.so file to the apk lib directory
- Find the game activity and paste the following code inside `onCreate` method (Edit all dex with MT Manager)

```
const-string v0, "Tool"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

# Security

## CRC32

- Extract the `base.apk` from xapk
- Open `Apkanalyzer+`, choose modded apk, `Modify New Apk Old set Entry` and select `base.apk`
- Disable `set old time`
- Patch

## pairip

- Recognize: `IndexOutOfBoundsException` while dumping
- Open MT Manager
- Edit all Dex files
- Search for signaturecheck
- Click the result in the following path: com.pairip.application/Application/invoke-static...
- Remove `attachBaseContext` (method that contains invoke-static...)
- Open `com/Unity3d/player/UnityPlayerActivity`, find on `onCreate` method: `invoke-static {p0} Lcom/pairip/licensecheck...` and remove
- Recompile and apply CRC32
