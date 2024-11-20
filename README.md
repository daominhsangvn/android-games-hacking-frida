## Prerequisites
- Python 3.12+
- NodeJS 20
- Frida 16.4.10
- frida-tools 12.5.1
- Emulator: Bluestacks Pie x64
- APK: armeabi-v7a
- ADB

## Installation
- ADB
    - Download sdk tool at https://dl.google.com/android/repository/platform-tools-latest-windows.zip
    - Unzip and copy `platform-tools` to `C:\Users\USERNAME\AppData\Local\Android\sdk` (Create folder if not exists)
    - Add `C:\Users\USERNAME\AppData\Local\Android\sdk\platform-tools` to your `PATH`
    - Test ADB `adb devices`
- Install Frida Tools `pip install frida-tools==12.5.1`
    - Test Frida `frida-ps`
- Install NodeJS 20
- Install Frida Server To Emulator
    - Download Frida Server frida-server-xx.x.xx-android-x86.xz (x86_64 for 64-bit emulator only) on https://github.com/frida/frida/releases, unzip and rename to `frida-server`
    - Push Frida Server to emulator `adb push frida-server /data/local/tmp`
    - Enable root
    - `adb shell`
    - `su`
    - `chmod +x /data/local/tmp/frida-server`
    - `chmod 755 /data/local/tmp/frida-server`
    - Start Frida Server `/data/local/tmp/frida-server &`
    - Test: `frida-ps -U -a`
- Install Frida Server with Magisk https://github.com/ViRb3/magisk-frida/releases

## Start Scripting
- Run `npm run watch` to 
- Start game
- Then wait for a while and run `spawn` command
    - `npm run spawn <game_id>`: For non-libil2cpp game (cocos)
    - `npm run spawn2 <game_id>`: For 32bit emulator
    - `npm run spawn4 <game_id> <process_id>`: For libil2cpp game (arm64-v8a)
        - Start game first then run `frida-ps -U -a` to get process id

## Troubleshooting
- `Failed to enumerate applications: unable to handle 64-bit processes due to build configuration`
```
Use x86_64 if you're using x86
```
- `Cannot find emulator in adb devices command`
```
adb kill-server then adb start-server
```
- `ModuleNotFoundError: No module named '_frida'`
```
Re-install frida-tools (uninstall first) then python -m pip install frida-tools
```
- `libil2cpp.so not found`
```
Try to use realm emulated npm run spawn2
May be need to start game first then run command later
```
- `Failed to spawn: need Gadget to attach on jailed Android;`
```
Push frida-gadge to same location as frida-server
```
- `Failed to spawn: need Gadget to attach on jailed Android; its default location is: C:\Users\xxx\AppData\Local\Microsoft\Windows\INetCache\frida\gadget-android-arm64.so`
```
Restart the frida-server in emulator
```