# Tutorials
## Ta La Dao Sy Xuat Quan
1. Dump the game Il2CppDump Gui
2. Decompile the game with APK Easy Tool
3. Use dnsSpy to open all file in DumpDll folder and find offset
4. Apply
  4.1. Direct to il2cpp.so file
    - Open lib folder and delete arm64-v8a
    - Use HexEditor (HxD) and open armeabi-v7a/il2cpp.so
    - Ctrl + G to open find offset window (paste offset without 0x)
    - Replace lát 8 bytes and replace with true/false in bytes
    - ApkEasyTool to compile
  4.2. Hook
