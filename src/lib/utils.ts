import "frida-il2cpp-bridge";

export const printLoadedModules = (delay: number = 15000) => {
  setTimeout(() => {
    // console.log('---------------------------------------------');
    Process.enumerateModules().forEach((module) => {
      console.log(`${module.name} - ${module.size} - ${module.path}`);
      // console.log(`Module Name: ${module.name}`);
      // console.log(`Base Address: ${module.base}`);
      // console.log(`Size: ${module.size}`);
      // console.log(`Path: ${module.path}`);
      // console.log('---');
    });
  }, delay);
};

export const findxxteakey = (activityName: string) => {
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
          console.log("key: " + Memory.readUtf8String(args[2])); // new!hy12m31dk23o
        },
        onLeave: function (retval) {},
      });
    };
  });
};

// Requirfred: frida-il2cpp-bridge
export const dumpIl2cpp = async () => {
  return new Promise((resolve, reject) => {
    console.log("Dumping il2cpp in 20 seconds...");
    sleep(20000).then(() => {
      console.log("Dumping il2cpp...");
      Il2Cpp.perform(() => {
        Il2Cpp.dump("dump.cs");
        resolve(true);
      });
    });
  });
};

export const findModuleByName = async (
  moduleName: string,
  timeout: number = 10000
) => {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const interval = 100; // Check every 100ms

    const checkModule = () => {
      const module = Process.findModuleByName(moduleName);
      if (module) {
        resolve(module);
      } else if (Date.now() - startTime > timeout) {
        reject(new Error(`Module ${moduleName} not found within ${timeout}ms`));
      } else {
        setTimeout(checkModule, interval);
      }
    };

    checkModule();
  });
};

export const awaitForIL2CPPLoad = async () => {
  console.log("Await for il2cpp load");
  const modulesList = ["libil2cpp.so"];
  await sleep(2000);
  await ensureModulesInitialized(...modulesList);
  console.log("Il2cpp loaded");
};

export function sleep(ms: number): Promise<number> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function ensureModulesInitialized(...modules: string[]) {
  while (modules.length > 0) {
    const md = modules.pop();
    if (!md) return;

    if (!Module.findBaseAddress(md)) {
      console.log(`Waiting for ${md} to be initialized...`);
      await sleep(100);
      modules.push(md);
    }
  }
}

export async function traceAll() {
  Il2Cpp.perform(() => {
    Il2Cpp.trace()
      .assemblies(Il2Cpp.domain.assembly("Assembly-CSharp"))
      .and()
      .attach();
  });
}

export async function traceClass(
  className: string,
  assemblyName: string = "Assembly-CSharp"
) {
  Il2Cpp.perform(() => {
    const image = Il2Cpp.domain.assembly(assemblyName).image;
    const tracer = image.class(className);
    // trace(true) will print the method arguments, but may get into error: access violation accessing 0x1
    // use trace() then trace(true) to prevent crash
    Il2Cpp.trace().classes(tracer).and().attach();
  });
}

// export async function decryptCocos2dlua() {
//   console.log("Starting decryptCocos2dlua function");

//   /*
//    * Find offset of "xxtea_decrypt" in your version of libcocos2dlua.so
//    *
//    * https://github.com/xpol/lua-cocos2d-x-xxtea/blob/66c3b2eb75a864baf350a191eb5a807f2028ff99/xxtea.h#L45
//    */
//   const XXTEA_DECRYPT_OFFSET = "0x00d8d1c4";
//   console.log(`XXTEA_DECRYPT_OFFSET: ${XXTEA_DECRYPT_OFFSET}`);

//   /*
//    * Library name of Cocos2D engine, most probably does not requires changes
//    */
//   const COCOS2D_LIB_NAME = "libcocos2dlua.so";
//   console.log(`COCOS2D_LIB_NAME: ${COCOS2D_LIB_NAME}`);

//   let LAST_OPENED_LUAC_FILE: string | null = null;
//   let FIRST_DETECT = true;

//   function stringToHex(inputString: string): string {
//     console.log("Converting string to hex");
//     let hexString = "";
//     for (let i = 0; i < inputString.length; i++) {
//       const hex = inputString.charCodeAt(i).toString(16);
//       hexString += hex.padStart(2, "0");
//     }
//     console.log(`Converted hex string: ${hexString.substring(0, 20)}...`);
//     return hexString;
//   }

//   function intercept_xxtea_decryptor() {
//     console.log("Intercepting xxtea_decryptor");
//     const cocosLib = Module.findBaseAddress(COCOS2D_LIB_NAME);
//     if (!cocosLib) {
//       console.error(`Failed to find base address for ${COCOS2D_LIB_NAME}`);
//       return;
//     }

//     // xxtea_decrypt
//     Interceptor.attach(cocosLib.add(ptr(XXTEA_DECRYPT_OFFSET)), {
//       onEnter: function (args) {
//         console.log("Entered xxtea_decrypt function");
//         console.log(`Args[3] as integer: ${args[3].toInt32()}`);
//         const key = Memory.readCString(args[2], 16);
//         console.log(
//           `xxtea_decrypt: file=${LAST_OPENED_LUAC_FILE}, key=${key}, keyLen=${args[3]}`
//         );
//       },
//       onLeave: function (retval) {
//         console.log("Leaving xxtea_decrypt function");
//         const content = Memory.readCString(retval);
//         if (content) {
//           console.log(`Decrypted content length: ${content.length}`);
//           send(
//             JSON.stringify({
//               file: LAST_OPENED_LUAC_FILE,
//               content: stringToHex(content),
//             })
//           );
//         } else {
//           console.error("Failed to read decrypted content");
//         }
//       },
//     });
//   }

//   const openExport = Module.findExportByName(null, "open");
//   if (!openExport) {
//     console.error("Failed to find 'open' export");
//     return;
//   }

//   Interceptor.attach(openExport, {
//     onEnter: function (args) {
//       // console.log("Entered 'open' function");
//       const filePath = Memory.readUtf8String(args[0]);
//       if (filePath) {
//         // console.log(`Opened file: ${filePath}`);
//         if (filePath.indexOf(".lua") > -1) {
//           LAST_OPENED_LUAC_FILE = filePath;
//           console.log(`Detected .luac file: ${LAST_OPENED_LUAC_FILE}`);
//           if (FIRST_DETECT) {
//             console.log("First .luac file detected, intercepting xxtea_decryptor");
//             intercept_xxtea_decryptor();
//             FIRST_DETECT = false;
//           }
//         }
//       } else {
//         console.error("Failed to read file path");
//       }
//     },
//   });

//   console.log("decryptCocos2dlua function setup complete");
// }
