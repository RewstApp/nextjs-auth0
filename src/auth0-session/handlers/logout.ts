import urlJoin from 'url-join';
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
  const clearOptions = {
    path: cookieConfig.path || '/',
    domain: cookieConfig.domain,
    secure: cookieConfig.secure !== false,
    httpOnly: cookieConfig.httpOnly !== false,
    sameSite: cookieConfig.sameSite,
    partitioned: cookieConfig.partitioned
  };

  // Remove undefined values to avoid issues with cookie serialization
  Object.keys(clearOptions).forEach(key => {
    if (clearOptions[key as keyof typeof clearOptions] === undefined) {
      delete clearOptions[key as keyof typeof clearOptions];
    }
  });

  res.clearCookie(cookieName, clearOptions);
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
