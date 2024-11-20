const { spawn } = require("child_process");

const gameId = process.argv[2];

if (!gameId) {
    console.error("Game id is required");
    process.exit(1);
}

const args = [`-U`, `-f`, `${gameId}`,'--realm', `emulated`, `-l`, `dist/games/${gameId}/agent.js`];

console.log("WARNING: You need to run the app first before running this script");
console.log("Executing: frida", args.join(" "));

spawn('frida', args, { stdio: 'inherit' });