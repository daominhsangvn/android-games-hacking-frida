import "frida-il2cpp-bridge";

import {
  ensureModulesInitialized,
  printLoadedModules,
  sleep,
} from "./lib/utils.js";

// spawn2
setImmediate(async () => {
  // dumpIl2cpp();
  // printLoadedModules(20000);
  const modulesList = ["libil2cpp.so"];
  await sleep(2000);
  await ensureModulesInitialized(...modulesList);
  console.log("Modules initialized");
  var il2cpp = Module.findBaseAddress("libil2cpp.so") as NativePointer;
  await attachHacks(il2cpp);
});

async function attachHacks(il2cpp: NativePointer) {
  // Interceptor.attach(il2cpp.add(functionAddress),{
  //     onEnter: function(args){
  //         // On enter function
  //     },
  //     onLeave: function(resoult){
  //         // On enter function
  //     }
  // })
  console.log("Attach hacks");
  Il2Cpp.perform(() => {
    const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    Il2Cpp.trace(true).classes().and().attach();
  });
  // Hooking the constructor of HeroData to monitor health changes
  // const heroDataCtor = il2cpp.add(0x186C6D0);
  // Interceptor.attach(heroDataCtor, {
  //   onEnter: function (args) {
  //     console.log("HeroData constructor called");
  //     console.log("Initial HP: " + args[4].toDouble());
  //   },
  //   onLeave: function (result) {
  //     console.log("HeroData constructor finished");
  //   },
  // });

  // // Hooking the constructor of FightHeroData to monitor attack-related fields
  // const fightHeroDataCtor = il2cpp.add(0x1492858);
  // Interceptor.attach(fightHeroDataCtor, {
  //   onEnter: function (args) {
  //     console.log("FightHeroData constructor called");
  //     console.log("Initial Crit: " + args[5].toFloat());
  //     console.log("Initial Extrahurt: " + args[6].toFloat());
  //   },
  //   onLeave: function (result) {
  //     console.log("FightHeroData constructor finished");
  //   },
  // });

  // Il2Cpp.perform(() => {
  //   const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
  //   const HeroData = AssemblyCSharp.class("HeroData");
  //   Il2Cpp.trace(true).classes(HeroData).and().attach();
  // });
}

// Java.perform(async () => {
//   //   const modulesList = ["libil2cpp.so"];
//   //   await sleep(2000);
//   //   await ensureModulesInitialized(...modulesList);
//   //   console.log("Modules initialized");
//   //   var il2cpp = Module.findBaseAddress('libil2cpp.so') as NativePointer;
//   printLoadedModules(20000);
// });
