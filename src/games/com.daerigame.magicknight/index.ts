import { awaitForIL2CPPLoad, dumpIl2cpp, sleep, traceClass } from "../../lib/utils.js";

setImmediate(async () => {
  await awaitForIL2CPPLoad();
  await sleep(5000);

//   await dumpIl2cpp();
    await attachHacks();
});

async function attachHacks() {
    console.log("attachHacks");
    await traceClass("CharacterData", "DPoly.Source");
    // Il2Cpp.perform(() => {
    //     const image = Il2Cpp.domain.assembly("DPoly.Source").image;
    //     const GMCommands = image.class("Modules.Utils.GMCommands");
    //     const AtkAdd = GMCommands.method<void>("AtkAdd");
    //     setTimeout(() => {
    //         console.log("AtkAdd()");
    //         AtkAdd.invoke();
    //     }, 50000)
    // });
}
