1. Move the libTool.so file to the apk lib directory
2. Open APKToolGui to find the activity name (APK Info tab)
3. Open MT Manager > Open any Dex file > Choose Dex Editor Plus > Select All
4. Open tab Search and find by activity name in #2, change Search Type to Class name
5. Open the activity search result, find onCreate and insert the following right below `.registers <number>`
```
const-string v0, "Tool"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```