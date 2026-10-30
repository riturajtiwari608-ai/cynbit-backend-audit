import { createServer } from './server.js';
import { config } from './config.js';

const server = createServer();

server.listen(config.port, () => {
  console.log('\n=============================================================');
  console.log('🚀 CYNBIT BACKEND HARDENED REFERENCE ARCHITECTURE RUNNING');
  console.log(`   Local Server  : http://localhost:${config.port}`);
  console.log(`   Interactive UI: http://localhost:${config.port}/`);
  console.log(`   Health Status : http://localhost:${config.port}/api/health`);
  console.log('   Environment   :', config.nodeEnv);
  console.log('   Candidate     : Rituraj Tiwari (cmtykw6c0000004igfwa7a18q)');
  console.log('=============================================================\n');
});
