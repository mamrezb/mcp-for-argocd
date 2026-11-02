import { readFileSync } from 'node:fs';

export const fixedArgoCDCredentials = (): { argocdBaseUrl: string; argocdApiToken: string } => {
  const argocdBaseUrl = process.env.ARGOCD_BASE_URL || '';
  let url: URL;
  try {
    url = new URL(argocdBaseUrl);
  } catch {
    throw new Error('WorkOS requires a fixed ARGOCD_BASE_URL');
  }
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      'ARGOCD_BASE_URL must be an HTTP(S) URL without credentials, query or fragment'
    );
  }
  if (process.env.ARGOCD_TOKEN_REGISTRY_PATH) {
    throw new Error('WorkOS cannot use an ArgoCD token registry');
  }
  const file = process.env.ARGOCD_API_TOKEN_FILE;
  if (file && process.env.ARGOCD_API_TOKEN !== undefined) {
    throw new Error('Set only one of ARGOCD_API_TOKEN_FILE and ARGOCD_API_TOKEN');
  }
  let argocdApiToken: string;
  try {
    argocdApiToken = (
      file ? readFileSync(file, 'utf8') : process.env.ARGOCD_API_TOKEN || ''
    ).trim();
  } catch {
    throw new Error('Unable to read ARGOCD_API_TOKEN_FILE');
  }
  if (!argocdApiToken || /\s/.test(argocdApiToken)) {
    throw new Error('WorkOS requires a non-empty fixed ArgoCD API token');
  }
  return { argocdBaseUrl, argocdApiToken };
};
