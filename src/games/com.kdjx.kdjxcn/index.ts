import { decryptCocos2dlua } from "../../lib/utils.js"

// com.kdjx.kdjxcn/org.cocos2dx.lua.AppActivity
Java.perform(() => {
  // Find activity class by: adb shell dumpsys package com.snmjglo.google | grep -A1 "android.intent.action.MAIN:"
  var Cocos2dxActivity = Java.use("com.cocos.game.AppActivity"); // Example: "com.cocos.game.AppActivity"
  Cocos2dxActivity.onLoadNativeLibraries.implementation = function () {
    console.log("Cocos2dxActivity.onLoadNativeLibraries() called");
    this.onLoadNativeLibraries();
    var target = Module.findExportByName("libcocos2dlua.so", "xxtea_decrypt");
    if (target == null) {
      console.log("xxtea_decrypt not found");
      return;
    }
    Interceptor.attach(target, {
      onEnter: function (args) {
        console.log("xxtea_decrypt called");
        // @ts-ignore
        console.log("key: " + Memory.readUtf8String(args[2])); // new!hy12m31dk23o
      },
      onLeave: function (retval) {},
    });
  };
});

setImmediate(() => {   
    decryptCocos2dlua()
 })
