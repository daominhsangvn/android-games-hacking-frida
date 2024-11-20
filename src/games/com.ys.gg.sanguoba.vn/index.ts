import "frida-il2cpp-bridge";
import { awaitForIL2CPPLoad, sleep, traceClass } from "../../lib/utils.js";

console.log("com.ys.gg.sanguoba.vn");

// spawn2
setImmediate(async () => {
  await awaitForIL2CPPLoad();
  // await sleep(30000);
  // await traceClass("Combat.ECS.Systems.BulletDamageSystem", "Combat.Runtime");
  // await traceClass("Combat.ECS.Systems.EnemySpawnSystem", "Combat.Runtime");

  // await dumpIl2cpp();

  await attachHacks();
});

async function attachHacks() {
  console.log("attachHacks");
  Il2Cpp.perform(() => {
    const image = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const GMCommands = image.class("Modules.Utils.GMCommands");
    const AtkAdd = GMCommands.method<void>("AtkAdd");
    setTimeout(() => {
      console.log("AtkAdd()");
      AtkAdd.invoke();
    }, 50000)
  });
}
