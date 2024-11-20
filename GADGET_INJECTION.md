# Inject Frida Gadget into APK for Non-Root Device
## Prerequisite
- APK ToolGUI
- Frida Gadget `frida-gadget-xx.x.x-android-xx.so.xz`
    - Download architectures depends on game architectures
    - Get device architecture: `adb shell getprop ro.product.cpu.abi`
- Objection for final packing: https://github.com/sensepost/objection

## Steps to inject Frida Gadget into APK
1. Open APK ToolGUI, drop APK file to `APK/XAPK/APKS/ZIP/APKM File:`, it will auto decompile
2. Copy `frida-gadget-xx.x.x-android-xx.so` to each architecture folder as `libfrida-gadget.so`
3. Inject library load to main activity
    - Find main activity file:
        + APK ToolGUI: `Main` -> `Main activity smali`
        + Open the decompiled folder and searching for the activity. tip: if activity name is`com.cocos.game.AppActivity` then search for `com/cocos/game/AppActivity` or `public Lcom/cocos/game/AppActivity`
    - Find the `onCreate(Landroid/os/Bundle;)` and insert the following code just right below `.locals x` (the code line right below onCreate)
    ```
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    ```
4. Add permission `<uses-permission android:name="android.permission.INTERNET" />` to `AndroidManifest.xml`
5. Recompile APK using APK ToolGUI (`Main` > `Compile` button)

### Inject Automatically
1. `pip install frida-gadget --upgrade`
2. `frida-gadget handtrackinggpu.apk --arch arm64 --sign`

## Use Frida Gadget
1. Start app, white screen is normal, library has opened a tcp socket and waits for a connection from frida at port 27042.
2. `frida-ps -U` to list all running process. Expect to see a process with name `Gadget`
3. `frida -U Gadget` to connect to the process

## Packing js into APK
1. (optional) create `libgadget.config.so` (https://github.com/darvincisec/InjectFridaGadget)
```
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/myscript.js",
    "on_change": "reload"
  }
}
```
2. create `config.json`
```
{
  "interaction": {
    "type": "script",
    "path": "libfrida-gadget.script.so"
  }
}
```
3. `objection patchapk -s pl.netigen.kittycorn.apk -c config.json -l script.js`
