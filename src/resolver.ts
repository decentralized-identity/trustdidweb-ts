import { Elysia } from 'elysia'
import { getLatestDIDDoc, getLogFile } from './routes/did';
import { createWitnessProof } from './witness';

const app = new Elysia()
  .get('/health', 'ok')
  .get('/.well-known/did.jsonl', () => console.log('base domain log queried'))
  .post('/witness', async ({body}) => {
    console.log('signing')
    const result = await createWitnessProof((body as any).log);
    if ('error' in result) {
      return { error: result.error };
    }
    return { proof: result.proof };
  })
  .group('/:id', app => {
    return app
      .get('/did.jsonl', ({params}) => getLogFile({params: {scid: params.id}}))
      .get('/:version', ({params: {id, version}}) => {
        console.log(version)
      })
      .get('/versions', ({params: {id}}) => {
        console.log('versions')
      })
      .post('/witness', ({params, body}) => {
        // TODO FINISH WITNESS CODE
        return {
          proof: {
            type: "DataIntegrityProof",
            cryptosuite: 'eddsa-jcs-2022'
          }
        }
      })
      .get('/', ({params, set}) => getLatestDIDDoc({params}))
    })
	.listen(8000)


console.log(`🔍 Resolver is running at on port ${app.server?.port}...`)
