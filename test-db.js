import pg from 'pg';
const { Pool } = pg;

const pool = new Pool({
  connectionString: 'postgresql://postgres:Fugle123@localhost:5432/mxbikes_stats'
});

console.log('Testing database performance...\n');

console.time('Players count');
const players = await pool.query('SELECT count(*) FROM players');
console.timeEnd('Players count');
console.log('Total players:', players.rows[0].count);

console.time('Sessions count');
const sessions = await pool.query('SELECT count(*) FROM sessions');
console.timeEnd('Sessions count');
console.log('Total sessions:', sessions.rows[0].count);

console.time('Leaderboard query');
const leaderboard = await pool.query('SELECT * FROM players ORDER BY mmr DESC LIMIT 50');
console.timeEnd('Leaderboard query');
console.log('Leaderboard rows:', leaderboard.rows.length);

console.time('Recent sessions');
const recent = await pool.query('SELECT * FROM sessions ORDER BY "createdAt" DESC LIMIT 20');
console.timeEnd('Recent sessions');
console.log('Recent sessions:', recent.rows.length);

console.time('Online players');
const online = await pool.query(`SELECT * FROM players WHERE "lastSeen" > $1`, [Date.now() - 300000]);
console.timeEnd('Online players');
console.log('Online players:', online.rows.length);

await pool.end();
console.log('\nDone!');
