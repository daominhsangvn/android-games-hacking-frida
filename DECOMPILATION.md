1. Getting APK file
- Get file paths of installed app `adb shell pm path <package_name>`
- Copy APK file to PC `adb pull <path_on_device> <path_on_pc>`
    - You should pull 2 files `base.apk` and `split_config.xxx.apk`

2. Unpack APK
- Decompile `apktool d base.apk -r` (or without `-r` if you want to edit smali code)

3. Decompilation
- Unzip `base.apk`
- Convert `dex` to `jar`: `d2j-dex2jar classes.dex` (Shoudl convert all dexes to find relevant code)

4. Analyze
- Use `JD-GUI` to open `classes.jar`
- Convert `jar` to `java`: `jadx -r -d <path_to_save> <path_to_jar>`

# Apk Easy Tool
