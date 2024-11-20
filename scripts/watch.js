const { spawn } = require("child_process");

const gameId = process.argv[2];

if (!gameId) {
    console.error("Game id is required");
    process.exit(1);
}

const args = [`src/games/${gameId}/index.ts`, '-o', `dist/games/${gameId}/agent.js`, '-w'];

spawn('frida-compile', args, { stdio: 'inherit' });