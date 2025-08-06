const urlJoin = require('url-join');
import createDebug from '../utils/debug';
import { GetConfig, LogoutOptions } from '../config';
import { SessionCache } from '../session-cache';
import { Auth0Request, Auth0Response } from '../http';
import { GetClient } from '../client/abstract-client';

const debug = createDebug('logout');

export type HandleLogout = (req: Auth0Request, res: Auth0Response, options?: LogoutOptions) => Promise<void>;

/**
 * Remove a cookie by creating a matching removal header with all possible attributes
 */
function removeCookie(res: Auth0Response, cookieName: string, cookieConfig: any = {}) {
  let cookieString = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;

  // Add path (default to '/')
  const path = cookieConfig.path || '/';
  cookieString += `; Path=${path}`;

  // Add domain if specified
  if (cookieConfig.domain) {
    cookieString += `; Domain=${cookieConfig.domain}`;
  }

  // Add security attributes to match original cookie
  if (cookieConfig.secure !== false) {
    cookieString += '; Secure';
  }

  if (cookieConfig.httpOnly !== false) {
    cookieString += '; HttpOnly';
  }

  if (cookieConfig.sameSite) {
    cookieString += `; SameSite=${cookieConfig.sameSite}`;
  }

  if (cookieConfig.partitioned) {
    cookieString += '; Partitioned';
  }

  // Add to existing Set-Cookie headers
  const existingCookies = res.res.getHeader('Set-Cookie') || [];
  const cookieArray = Array.isArray(existingCookies) ? existingCookies : [existingCookies as string];
  cookieArray.push(cookieString);

  res.res.setHeader('Set-Cookie', cookieArray);
}

export default function logoutHandlerFactory(
  getConfig: GetConfig,
  getClient: GetClient,
  sessionCache: SessionCache
): HandleLogout {
  const getConfigFn = typeof getConfig === 'function' ? getConfig : () => getConfig;
  return async (req, res, options = {}) => {
    const config = await getConfigFn(req);
    const client = await getClient(config);
    let returnURL = options.returnTo || config.routes.postLogoutRedirect;
    debug('logout() with return url: %s', returnURL);

    try {
      new URL(returnURL);
    } catch (_) {
      returnURL = urlJoin(config.baseURL, returnURL);
    }

    const isAuthenticated = await sessionCache.isAuthenticated(req.req, res.res);

    if (!isAuthenticated) {
      debug('end-user already logged out, redirecting to %s', returnURL);
      res.redirect(returnURL);
      return;
    }

    const idToken = await sessionCache.getIdToken(req.req, res.res);

    await sessionCache.delete(req.req, res.res);

    // Remove the session cookie with matching attributes
    const cookieName = config.session?.name || 'appSession';

    removeCookie(res, cookieName, config.session?.cookie);
    
    // Also remove with partitioned flag to ensure cleanup regardless of original cookie config
    const cookieConfigWithPartitioned = {
      ...config.session?.cookie,
      partitioned: true
    };
    removeCookie(res, cookieName, cookieConfigWithPartitioned);
    
    debug('session cookie cleared');

    if (!config.idpLogout) {
      debug('performing a local only logout, redirecting to %s', returnURL);
      res.redirect(returnURL);
      return;
    }

    returnURL = await client.endSessionUrl({
      ...options.logoutParams,
      post_logout_redirect_uri: returnURL,
      id_token_hint: idToken
    });

    debug('logging out of identity provider, redirecting to %s', returnURL);
    res.redirect(returnURL);
  };
}
