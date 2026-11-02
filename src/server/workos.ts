import type express from 'express';
import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';

export type WorkOSOptions = {
  authkitDomain: string;
  resourceUrl: string;
  allowedEmailDomain: string;
};

export const workOSOptionsFromEnv = (): WorkOSOptions | undefined => {
  const values = [
    process.env.WORKOS_AUTHKIT_DOMAIN,
    process.env.WORKOS_RESOURCE_URL,
    process.env.WORKOS_ALLOWED_EMAIL_DOMAIN
  ];
  if (values.every((value) => value === undefined)) return undefined;
  if (values.some((value) => !value?.trim())) {
    throw new Error(
      'WorkOS requires WORKOS_AUTHKIT_DOMAIN, WORKOS_RESOURCE_URL and WORKOS_ALLOWED_EMAIL_DOMAIN'
    );
  }
  return {
    authkitDomain: values[0]!,
    resourceUrl: values[1]!,
    allowedEmailDomain: values[2]!
  };
};

const httpsUrl = (raw: string): URL => {
  const url = new URL(raw);
  if (
    url.protocol !== 'https:' ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    /[\\\s?#]/.test(raw)
  ) {
    throw new Error('WorkOS URLs must be HTTPS URLs without credentials, queries or fragments');
  }
  return url;
};

// Bound provider responses and never follow redirects with a caller's token.
// The same fetch implementation is used for JWKS, metadata and userinfo.
const providerFetch: typeof fetch = async (input, init) => {
  const response = await fetch(input, {
    ...init,
    redirect: 'error',
    signal: AbortSignal.timeout(10_000)
  });
  if (!response.ok || !response.body) {
    await response.body?.cancel();
    throw new Error('WorkOS request failed');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 64 * 1024) throw new Error('WorkOS response is too large');
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  return new Response(Buffer.concat(chunks), {
    status: response.status,
    headers: { 'content-type': 'application/json' }
  });
};

export class WorkOSAuth {
  readonly issuer: string;
  readonly resource: URL;
  private readonly emailDomain: string;
  private readonly metadataUrl: string;
  private readonly keys: ReturnType<typeof createRemoteJWKSet>;

  constructor(options: WorkOSOptions) {
    const issuer = httpsUrl(options.authkitDomain);
    this.resource = httpsUrl(options.resourceUrl);
    if (issuer.pathname !== '/' || options.resourceUrl !== this.resource.href) {
      throw new Error('WorkOS requires an AuthKit origin and a canonical resource URL');
    }
    if (this.resource.pathname !== '/mcp') {
      throw new Error('WORKOS_RESOURCE_URL must identify the /mcp endpoint');
    }
    if (!/^[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}$/i.test(options.allowedEmailDomain)) {
      throw new Error('WORKOS_ALLOWED_EMAIL_DOMAIN must be one exact email domain');
    }
    this.issuer = issuer.origin;
    this.emailDomain = options.allowedEmailDomain.toLowerCase();
    this.metadataUrl = `${this.resource.origin}/.well-known/oauth-protected-resource/mcp`;
    this.keys = createRemoteJWKSet(new URL(`${this.issuer}/oauth2/jwks`), {
      [customFetch]: providerFetch,
      timeoutDuration: 10_000,
      cooldownDuration: 30_000,
      cacheMaxAge: 3_600_000
    });
  }

  registerRoutes(app: express.Express): void {
    app.use((req, res, next) => {
      if (
        req.headers.host?.toLowerCase() !== this.resource.host ||
        (req.headers.origin !== undefined && req.headers.origin !== this.resource.origin)
      ) {
        res.status(403).json({ error: 'Invalid Host or Origin' });
        return;
      }
      next();
    });
    // Use the configured resource, never Host/X-Forwarded-* supplied by a client.
    app.get(
      ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'],
      (_req, res) => {
        res.json({
          resource: this.resource.href,
          authorization_servers: [this.issuer],
          scopes_supported: ['openid', 'email', 'profile', 'offline_access'],
          bearer_methods_supported: ['header']
        });
      }
    );
    app.get('/.well-known/oauth-authorization-server', async (_req, res) => {
      try {
        const response = await providerFetch(
          `${this.issuer}/.well-known/oauth-authorization-server`
        );
        const metadata = await response.json();
        if (metadata.issuer !== this.issuer) throw new Error('Unexpected issuer');
        res.json(metadata);
      } catch {
        res.status(502).json({ error: 'Authorization server metadata unavailable' });
      }
    });
  }

  middleware(): express.RequestHandler {
    return async (req, res, next) => {
      try {
        const match = /^Bearer\s+(\S+)$/i.exec(req.headers.authorization ?? '');
        if (!match) throw new Error('Missing bearer token');
        const token = match[1];
        const { payload, protectedHeader } = await jwtVerify(token, this.keys, {
          algorithms: ['RS256'],
          issuer: this.issuer,
          audience: this.resource.href,
          requiredClaims: ['exp', 'sub', 'client_id', 'sid', 'scope']
        });
        const scopes = typeof payload.scope === 'string' ? payload.scope.split(/\s+/) : [];
        if (
          !protectedHeader.kid ||
          protectedHeader.crit !== undefined ||
          payload.aud !== this.resource.href ||
          !payload.sub?.startsWith('user_') ||
          typeof payload.client_id !== 'string' ||
          !payload.client_id ||
          typeof payload.sid !== 'string' ||
          !payload.sid ||
          !Number.isSafeInteger(payload.exp) ||
          (payload.nbf !== undefined && !Number.isSafeInteger(payload.nbf)) ||
          !scopes.includes('openid') ||
          !scopes.includes('email')
        ) {
          throw new Error('Expected a Connect user grant');
        }
        const response = await providerFetch(`${this.issuer}/oauth2/userinfo`, {
          method: 'POST',
          headers: { authorization: `Bearer ${token}` }
        });
        // WorkOS may return HTTP 201 for a successful POST to userinfo.
        const profile = await response.json();
        const email = typeof profile.email === 'string' ? profile.email.split('@') : [];
        if (
          profile.sub !== payload.sub ||
          profile.email_verified !== true ||
          email.length !== 2 ||
          !email[0] ||
          email[1].toLowerCase() !== this.emailDomain ||
          payload.exp! <= Date.now() / 1000
        ) {
          throw new Error('Expected a matching verified profile');
        }
        for (const name of Object.keys(req.headers)) {
          if (
            ['authorization', 'proxy-authorization', 'cookie', 'x-access-token'].includes(name) ||
            name.startsWith('x-argocd-')
          ) {
            delete req.headers[name];
          }
        }
        next();
      } catch {
        res
          .set(
            'WWW-Authenticate',
            `Bearer resource_metadata="${this.metadataUrl}", scope="openid email"`
          )
          .set('Cache-Control', 'no-store')
          .status(401)
          .json({ error: 'Missing or invalid WorkOS access token' });
      }
    };
  }
}
