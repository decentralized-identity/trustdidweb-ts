import { Elysia } from 'elysia'
import { getLatestDIDDoc, getLogFileForBase, getLogFileForSCID } from './routes/did';
import { createWitnessProof } from './witness';

const app = new Elysia()
  .get('/health', 'ok')
  .get('/.well-known/did.jsonl', () => getLogFileForBase())
  .post('/witness', async ({body}) => {
    const result = await createWitnessProof((body as any).log);
    console.log(`Signed with VM`, (result as any).proof.verificationMethod)
    if ('error' in result) {
      return { error: result.error };
    }
    return { proof: result.proof };
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
	.listen(8000)


console.log(`🔍 Resolver is running at on port ${app.server?.port}...`)
