import { Elysia } from 'elysia'
import { getLatestDIDDoc, getLogFile } from './routes/did';

const app = new Elysia()
  .get('/health', 'ok')
  .get('/.well-known/did.jsonl', () => console.log('base domain log queried'))
  .post('/witness', ({body}) => {
    console.log(body)
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
      .get('/', ({params, set}) => getLatestDIDDoc({params, set}))
    })
	.listen(8000)


console.log(`🔍 Resolver is running at on port ${app.server?.port}...`)
