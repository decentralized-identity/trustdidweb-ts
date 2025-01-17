import { Elysia } from 'elysia'
import { config } from './config';
import { resolveDID } from './method';
import { DIDDoc } from './interfaces';
import { getActiveDIDs } from './utils';

const WELL_KNOWN_ALLOW_LIST = ['did.jsonl'];

export const getFile = async ({
  params: {path, file}, 
  isRemote = false,
  didDocument
}: {
  params: {path: string; file: string}, 
  isRemote?: boolean,
  didDocument?: DIDDoc
}) => {
  try {
    if (isRemote) {
      let serviceEndpoint;
      
      if (file === 'whois') {
        const whoisService = didDocument?.service?.find(
          (s: any) => s.id === '#whois'
        );
        
        if (whoisService?.serviceEndpoint) {
          serviceEndpoint = whoisService.serviceEndpoint;
        }
      } else {
        const filesService = didDocument?.service?.find(
          (s: any) => s.id === '#files'
        );
        
        if (filesService?.serviceEndpoint) {
          serviceEndpoint = filesService.serviceEndpoint;
        }
      }

      if (!serviceEndpoint) {
        const cleanDomain = path.replace('.well-known/', '');
        serviceEndpoint = `https://${cleanDomain}`;
        
        if (file === 'whois') {
          serviceEndpoint = `${serviceEndpoint}/whois.vp`;
        }
      }
      serviceEndpoint = serviceEndpoint.replace(/\/$/, '');
      const url = file === 'whois' ? serviceEndpoint : `${serviceEndpoint}/${file}`;
      
      const response = await fetch(url);
      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('Error 404: Not Found');
        }
        throw new Error(`Error ${response.status}: ${response.statusText}`);
      }
      return response.text();
    }
    if (file === 'whois') {
      file = 'whois.vp';
    }
    const filePath = WELL_KNOWN_ALLOW_LIST.some(f => f === file) ? `./src/routes/.well-known/${file}` : path ? `./src/routes/${path}/${file}` : `./src/routes/${file}`
    return await Bun.file(filePath).text();
  } catch (e: unknown) {
    console.error(e);
    return new Response(JSON.stringify({
      error: 'Failed to resolve File',
      details: e instanceof Error ? e.message : String(e)
    }), {status: 404});
  }
}

const app = new Elysia()
  .get('/health', 'ok')
  .get('/resolve/:id', async ({ params: { id }, query }) => {
    try {
      if (!id) {
        throw new Error('No id provided');
      }

      const [didPart, ...pathParts] = id.split('/');
      if (pathParts.length === 0) {
        const options = {
          versionNumber: query.versionNumber ? parseInt(query.versionNumber as string) : undefined,
          versionId: query.versionId as string,
          versionTime: query.versionTime ? new Date(query.versionTime as string) : undefined,
          verificationMethod: query.verificationMethod as string
        };
        return await resolveDID(didPart, options);
      }
      
      const {did, doc, controlled} = await resolveDID(didPart);
      
      const didParts = did.split(':');
      const domain = didParts[didParts.length - 1];
      const fileIdentifier = didParts[didParts.length - 2];
      
      return await getFile({
        params: {
          path: !controlled ? domain : fileIdentifier,
          file: pathParts.join('/')
        },
        isRemote: !controlled,
        didDocument: doc
      });
    } catch (error: unknown) {
      console.error('Error resolving identifier:', error);
      return new Response(JSON.stringify({
        error: 'Resolution failed',
        details: error instanceof Error ? error.message : String(error)
      }), {status: 400});
    }
  })
  .get('/resolve/:id/*', async ({ params }) => {
    const pathParts = params['*'].split('/');
    return await getFile({
      params: {
        path: pathParts.slice(0, -1).join('/'),
        file: pathParts[pathParts.length - 1]
      },
      isRemote: false
    });
  })
  .get('/.well-known/*', async ({ params }) => {
    const file = params['*'];
    return await getFile({
      params: {
        path: '.well-known',
        file
      },
      isRemote: false
    });
  })

const port = config.getEnvValue('PORT') || 8000;

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
