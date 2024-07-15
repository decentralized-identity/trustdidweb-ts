import { Elysia } from 'elysia'
import { getLatestDIDDoc, getLogFile } from './routes/did';

const app = new Elysia()
  .group('/:id', app => {
    return app
      .get('/did.jsonl', ({params}) => getLogFile({params: {scid: params.id}}))
	    .get('/', ({params, set}) => getLatestDIDDoc({params, set}))
      .get('/:version', ({params: {id, version}}) => {
        console.log(version)
      })
      .get('/versions', ({params: {id}}) => {
        console.log('versions')
      })
  })
	.listen(8000)


console.log(`🔍 Resolver is running at on port ${app.server?.port}...`)
