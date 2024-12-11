import { Elysia } from 'elysia'
import { getLatestDIDDoc, getLogFileForBase, getLogFileForSCID } from './routes/did';
import { createWitnessProof } from './witness';
import { config } from './config';

const app = new Elysia()
  .get('/health', 'ok')
  .get('/.well-known/did.jsonl', () => getLogFileForBase())
  .post('/witness', async ({body}) => {
    try {
      const result = await createWitnessProof((body as any).log);
      if ('error' in result) {
        throw new Error(result.error);
      }
      console.log(`Signed with VM`, (result as any).proof.verificationMethod)
      return { proof: result.proof };
    } catch (error) {
      console.error('Error creating witness proof:', error);
      return new Response(JSON.stringify({ error }), { status: 400 });
    }
  })
  .group('/:id', app => {
    return app
      .get('/did.jsonl', ({params}) => getLogFileForSCID({params: {scid: params.id}}))
      .get('/:version', ({params: {id, version}}) => {
        console.log(version)
      })
      .get('/versions', ({params: {id}}) => {
        console.log('versions')
      })
      .get('/', ({params}) => getLatestDIDDoc({params}))
    })

const port = config.getEnvValue('PORT') || 8000;

// Get verification methods using the config helper
const verificationMethods = config.getVerificationMethods();

// Function to get all active DIDs from verification methods
async function getActiveDIDs(): Promise<string[]> {
  const activeDIDs: string[] = [];
  
  try {
    // Get unique DIDs from verification methods
    for (const vm of verificationMethods) {
      const did = vm.controller || vm.id.split('#')[0];
      activeDIDs.push(did);
    }
  } catch (error) {
    console.error('Error processing verification methods:', error);
  }
  
  return activeDIDs;
}

// Log active DIDs when server starts
app.onStart(async () => {
  console.log('\n=== Active DIDs ===');
  const activeDIDs = await getActiveDIDs();
  
  if (activeDIDs.length === 0) {
    console.log('No active DIDs found');
  } else {
    activeDIDs.forEach(did => console.log(did));
  }
  console.log('=================\n');
});

console.log(`🔍 Resolver is running at http://localhost:${port}`);
app.listen(port);
