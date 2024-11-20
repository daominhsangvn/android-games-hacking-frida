const findxxteakey = (activityName: string) => {
  Java.perform(() => {
    // Find activity class by: adb shell dumpsys package com.snmjglo.google | grep -A1 "android.intent.action.MAIN:"
    var Cocos2dxActivity = Java.use(activityName); // Example: "com.cocos.game.AppActivity"
    Cocos2dxActivity.onLoadNativeLibraries.implementation = function () {
      console.log("Cocos2dxActivity.onLoadNativeLibraries() called");
      this.onLoadNativeLibraries();

      var target = Module.findExportByName("libcocos.so", "xxtea_decrypt");
      if (target == null) {
        console.log("xxtea_decrypt not found");
        return;
      }
      Interceptor.attach(target, {
        onEnter: function (args) {
          console.log("xxtea_decrypt called");
          // @ts-ignore
          console.log("key: " + Memory.readUtf8String(args[2]));
        },
        onLeave: function (retval) {},
      });
    };
  });
};

setImmediate(() => {
  // findxxteakey("com.cocos.game.AppActivity");
  // key is 909H8IWtRL+YRoUP
  // Decrypt the file: (python 3.12.6)
  // python src/packages/jsc_decryptor/jscd.py decrypt src/games/com.x.fish/index.jsc src/games/com.x.fish/out.js 909H8IWtRL+YRoUP
  // Encrypt the file:
  // python src/packages/jsc_decryptor/jscd.py encrypt src/games/com.x.fish/out.js src/games/com.x.fish/new.jsc 909H8IWtRL+YRoUP
});

