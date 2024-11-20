const { spawn } = require("child_process");

const gameId = process.argv[2];

if (!gameId) {
    console.error("Game id is required");
    process.exit(1);
}
const args = [`-U`, 'Gadget', `-l`, `dist/games/${gameId}/agent.js`];
console.log("Executing: frida", args.join(" "));
spawn('frida', args, { stdio: 'inherit' });