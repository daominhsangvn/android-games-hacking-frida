const { exec } = require("child_process");

const gameId = process.argv[2];

if (!gameId) {
    console.error("Game id is required");
    process.exit(1);
}

const command = `frida-compile src/games/${gameId}/index.ts -o dist/games/${gameId}/agent.js -c`;

exec(command, (error, stdout, stderr) => {
    if (error) {
        console.error(`Error compiling game: ${error}`);
        return;
    }
    console.log(`Game compiled successfully`);
    console.log(stdout)
    console.log(stderr)
});