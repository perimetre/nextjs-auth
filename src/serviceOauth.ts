/* eslint-disable @typescript-eslint/no-explicit-any */
import CookieSessionStoreSettings from '@auth0/nextjs-auth0/dist/session/cookie-store/settings';
import { ISession } from '@auth0/nextjs-auth0/dist/session/session';
import { ISessionStore } from '@auth0/nextjs-auth0/dist/session/store';
import { setCookies, parseCookies } from '@auth0/nextjs-auth0/dist/utils/cookies';
import { createState, decodeState } from '@auth0/nextjs-auth0/dist/utils/state';
import getSessionFromTokenSet from '@auth0/nextjs-auth0/dist/utils/session';
import { TokenSet } from 'openid-client';
import { NextApiRequest, NextApiResponse } from 'next';
import { AuthSettings } from './index';
import { isOriginAllowed, isTokenExpired, OAuth2Client } from './utils';
import logging from './logging';
import { HandleUserOptions, HandleSessionOptions, UserAuth } from './service';
import jwt from 'jsonwebtoken';

/**
 * @typedef AuthorizationParameters
 */
export interface AuthorizationParameters {
  scope?: string;
  state?: string;
  [key: string]: unknown;
}

/**
 * @typedef HandleLoginOauthOptions
 */
export type HandleLoginOauthOptions = {
  /**
   * A state handler callback. If provided will be called to get a state object to send in the authorization request
   *
   * @param {NextApiRequest} req The server request
   * @returns The state object to be sent in the authorization request and received back in the callback enpoint
   */
  getState?: (req: NextApiRequest) => Record<string, any>;

  /**
   * OAuth authorization parameters to be forwarded to the authorization server.
   */
  authParams?: AuthorizationParameters;

  /**
   * Redirect url after user session has been saved.
   */
  redirectTo?: string;
};

/**
 * @typedef HandleCallbackOauthOptions
 */
export type HandleCallbackOauthOptions = {
  /**
   * Redirect url after user session has been saved.
   */
  redirectTo?: string;

  /**
   * Identity validation hook. Will be called once the response payload has been decoded.
   *
   * If the current accessToken is expired it will try to refresh it with `onRefresh`.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {ISession} session The session payload received in callback
   * @param {object} state The state payload received in callback
   * @returns {ISession} The processed session payload that will actually be saved in session store
   */
  onUserLoaded?: (
    req: NextApiRequest,
    res: NextApiResponse,
    session: ISession,
    state: Record<string, any>
  ) => Promise<ISession>;
};

/**
 * @typedef HandleLogoutOauthOptions
 */
export type HandleLogoutOauthOptions = {
  /**
   * Redirect url after user session has been saved.
   */
  redirectTo?: string;
};

/**
 * Creates an instance of the auth service
 *
 * @param {AuthSettings} settings The settings used for the auth client
 * @param {ISessionStore} sessionStore An instance of the sessionStore to be used
 * @param {CookieSessionStoreSettings} sessionSettings An instance of the sessionStore settings
 * @param {OAuth2Client} oauthClient An instance of the OAuth client to be used
 * @returns {typeof authServiceOauth} The authService instance
 */
export const authServiceOauth = (
  settings: AuthSettings,
  sessionStore: ISessionStore,
  sessionSettings: CookieSessionStoreSettings,
  oauthClient: () => OAuth2Client
) => {
  /**
   * Make an error that falls back to "Unauthorized" if NOT `NODE_ENV === development`
   *
   * @param {string} message The detailed message to be used if `NODE_ENV === development`
   * @returns {Error} The error
   */
  const makeDevUnauthorizedError = async (message: string) => {
    const { NODE_ENV, OMIT_ERRORS } = await settings.authEnv();

    if (!OMIT_ERRORS || NODE_ENV === 'development') {
      return new Error(message);
    } else {
      return new Error('Unauthorized');
    }
  };

  /**
   * Creates an `ISession` object from a current `UserAuth`
   *
   * @param {UserAuth} auth The current `UserAuth`
   * @returns {ISession} The session object
   */
  const getSessionFromAuth = (auth: UserAuth): ISession => {
    const { accessToken, refreshToken } = auth;

    logging.debug(settings.authEnv, '[getSessionFromAuth] Decoding accessToken payload');

    const payload = jwt.decode(accessToken);

    if (!payload || typeof payload === 'string') {
      throw new Error('Invalid payload type');
    }

    return { accessToken, refreshToken, user: payload, createdAt: Date.now() };
  };

  /**
   * Returns whether or not the given session is valid.
   *
   * @param {ISession | null | undefined} session The session
   * @returns {boolean} whether or not the given session is valid.
   */
  const isSessionValid = (session?: ISession | null) => session && session.user && Object.keys(session.user).length > 0;

  /**
   * The login handler that must be called by an OAuth2 login API route.
   *
   * It will redirect the user to the authorization server endpoint for authentication/authorization
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {HandleLoginOauthOptions} oauthOptions The method options if any. Only used when you are implementing OAuth logins
   */
  const handleLogin = async (req: NextApiRequest, res: NextApiResponse, oauthOptions?: HandleLoginOauthOptions) => {
    try {
      if (!req) {
        throw new Error('Request is not available');
      }

      if (!res) {
        throw new Error('Response is not available');
      }

      if (!settings.oauthSettings) {
        throw new Error('oauthSettings setting property was not provided');
      }

      if (req.query.redirectTo) {
        if (typeof req.query.redirectTo !== 'string') {
          throw new Error('Invalid value provided for redirectTo, must be a string');
        }

        const allowedOrigins = (await settings.authEnv()).ALLOWED_ORIGINS;
        if (!isOriginAllowed(allowedOrigins, req.query.redirectTo)) {
          throw new Error('Invalid value provided for redirectTo, must be a relative url');
        }
      }

      logging.debug(
        settings.authEnv,
        '[handleLogin] preparing state to save in cookie before redirect to authorization endpoint'
      );

      const opt = oauthOptions || {};
      const getLoginState =
        opt.getState ||
        function getLoginState(): Record<string, any> {
          return {};
        };

      const {
        // Generate a state which contains a nonce, the redirectTo uri and potentially custom data
        state = createState({
          redirectTo: req.query?.redirectTo || oauthOptions?.redirectTo,
          ...getLoginState(req)
        }),
        ...authParams
      } = (opt && opt.authParams) || {};

      // Set the necessary cookies
      setCookies(req, res, [
        {
          name: 'a0:state',
          value: state,
          maxAge: 60 * 60
        }
      ]);

      logging.debug(settings.authEnv, '[handleLogin] redirecting to authorization endpoint');

      // Redirect to the authorize endpoint.
      oauthClient().authorize(req, res, { scope: settings.oauthSettings.scope, state, ...authParams });
    } catch (error) {
      logging.debug(settings.authEnv, '[handleLogin] catch', error);
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  /**
   * The callback handler that must be called by an OAuth2 callback API route.
   *
   * It will receive an authorization code, exchange it for access tokens, save the session and redirect to
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {HandleCallbackOauthOptions} oauthOptions The method options if any. Only used when you are implementing OAuth logins
   */
  const handleCallback = async (
    req: NextApiRequest,
    res: NextApiResponse,
    oauthOptions?: HandleCallbackOauthOptions
  ) => {
    if (!res) {
      throw new Error('Response is not available');
    }

    if (!req) {
      throw new Error('Request is not available');
    }

    if (!settings.oauthSettings) {
      throw new Error('oauthSettings setting property was not provided');
    }

    logging.debug(
      settings.authEnv,
      '[handleCallback] Reading state data from saved cookie to compare with the one sent in handleLogin'
    );

    // Parse the cookies.
    const cookies = parseCookies(req);

    // Require that we have a state.
    const state = cookies['a0:state'];
    if (!state) {
      throw new Error('Invalid request, an initial state could not be found');
    }

    logging.debug(
      settings.authEnv,
      '[handleCallback] Calling token endpoint to exchange authorization code for tokens'
    );

    const tokenSet = await oauthClient().authenticate(req, res);

    if (!tokenSet) {
      logging.debug(settings.authEnv, '[handleCallback] Could not get token set from authentication provider');
      // throw new Error('Could not get token set from authentication provider');
      res.redirect('/login');
    }
    logging.debug(settings.authEnv, '[handleCallback] Decoding state from cookie', tokenSet);

    const decodedState = decodeState(state);
    let session = getSessionFromAuth(tokenSet);

    // Run the identity validated hook.
    if (oauthOptions && oauthOptions.onUserLoaded) {
      logging.debug(settings.authEnv, '[handleCallback] Running the identity validated hook');
      session = await oauthOptions.onUserLoaded(req, res, session, decodedState);
      logging.debug(settings.authEnv, '[handleCallback] Finished running the identity validated hook');
    }

    logging.debug(settings.authEnv, '[handleCallback] Saving session and redirect to redirectTo');

    // Create the session.
    await sessionStore.save(req, res, session);

    // Redirect to the homepage or custom url.
    const redirectTo = (oauthOptions && oauthOptions.redirectTo) || decodedState.redirectTo || '/';
    res.writeHead(302, {
      Location: redirectTo
    });
    res.end();
  };

  /**
   * The logout handler that must be called by a logout API route.
   *
   * It will call the `onLogout` callback, then clear the server session for the given user.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {HandleLogoutOauthOptions} oauthOptions The method options if any. Only used when you are implementing OAuth logins
   */
  const handleLogout = async (req: NextApiRequest, res: NextApiResponse, oauthOptions?: HandleLogoutOauthOptions) => {
    try {
      if (!req) {
        throw new Error('Request is not available');
      }

      if (!res) {
        throw new Error('Response is not available');
      }

      const redirectTo =
        req.query.redirectTo || oauthOptions?.redirectTo || settings?.oauthSettings?.postLogoutRedirectUri;

      if (redirectTo) {
        if (typeof redirectTo !== 'string') {
          throw new Error('Invalid value provided for redirectTo, must be a string');
        }

        const allowedOrigins = (await settings.authEnv()).ALLOWED_ORIGINS;
        if (!isOriginAllowed(allowedOrigins, redirectTo)) {
          throw new Error('Invalid value provided for redirectTo, must be a relative url');
        }
      }

      logging.debug(settings.authEnv, '[handleLogout] reading session');

      // Get the current session
      const sessionPayload = await sessionStore.read(req);

      logging.debug(settings.authEnv, '[handleLogout] validating session');

      // If we have a session, continue
      if (isSessionValid(sessionPayload)) {
        logging.debug(settings.authEnv, '[handleLogout] session is valid');

        logging.debug(settings.authEnv, '[handleLogout] clearing session');

        await sessionStore.save(req, res, { accessToken: '', refreshToken: '', user: {}, createdAt: Date.now() });

        // Remove the cookies
        // Ref: https://github.com/auth0/nextjs-auth0/blob/master/src/handlers/logout.ts
        setCookies(req, res, [
          {
            name: sessionSettings.cookieName,
            value: '',
            maxAge: -1,
            path: sessionSettings.cookiePath,
            domain: sessionSettings.cookieDomain
          }
        ]);
      }

      if (redirectTo) {
        // Redirect to the logout endpoint.
        res.writeHead(302, {
          Location: redirectTo
        });
        res.end();
      }

      // If don't have a session just fake that succeded?
    } catch (error) {
      logging.debug(settings.authEnv, '[handleLogout] catch', error);
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  /**
   * Gets the current user session within the server.
   *
   * If the current accessToken is expired it will try to refresh it with `onRefresh`.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {HandleSessionOptions} options The method options if any
   * @returns {ISession | undefined} The current user session within the server.
   */
  const getSession = async (req: NextApiRequest, res: NextApiResponse, options?: HandleSessionOptions) => {
    try {
      if (!req) {
        throw new Error('Request is not available');
      }

      if (!res) {
        throw new Error('Response is not available');
      }

      logging.debug(settings.authEnv, '[getSession] reading session');

      // Get the current session
      let sessionPayload = await sessionStore.read(req);

      if (isSessionValid(sessionPayload)) {
        logging.debug(settings.authEnv, '[getSession] session is valid');

        sessionPayload = sessionPayload as ISession;

        // If we want to refresh the user
        if (!options?.skipRefresh) {
          if (!sessionPayload.refreshToken) {
            throw new Error('No refresh token available to refetch the profile');
          }

          logging.debug(settings.authEnv, '[getSession] checking if accessToken has expired');

          // If we should force refresh or the token is expired
          if (options?.forceRefresh || isTokenExpired(sessionPayload.accessToken)) {
            logging.debug(settings.authEnv, '[getSession] accessToken expired or options.forceRefresh is true');

            logging.debug(settings.authEnv, '[getSession] checking if refreshToken has NOT expired');
            // If the refresh is NOT expired
            if (!isTokenExpired(sessionPayload.refreshToken)) {
              logging.debug(settings.authEnv, '[getSession] refreshToken NOT expired');

              logging.debug(settings.authEnv, '[getSession] calling refresh token endpoint');

              // Call the refresh token endpoint
              const newTokens = await oauthClient().refresh(sessionPayload.refreshToken);
              if (!newTokens.accessToken) {
                logging.debug(settings.authEnv, '[getSession] could not refresh tokens');
                logging.debug(settings.authEnv, '[getSession] logging out user');
                // If we couldn't get new tokens, logout
                await handleLogout(req, res);
                return undefined;
              }

              logging.debug(settings.authEnv, '[getSession] call to refresh token endpoint finished successfully');

              // Update the session.
              sessionPayload = getSessionFromAuth({
                accessToken: newTokens.accessToken,
                refreshToken: newTokens.refreshToken || (sessionPayload?.refreshToken as string)
              });

              logging.debug(settings.authEnv, '[getSession] saving new refreshed session payload');

              // Create the session, which will store the user info.
              await sessionStore.save(req, res, sessionPayload);

              logging.debug(settings.authEnv, '[getSession] returning session');
              return sessionPayload;
            } else {
              logging.debug(settings.authEnv, '[getSession] refreshToken IS expired');
              if (isSessionValid(sessionPayload)) {
                logging.debug(settings.authEnv, '[getSession] logging out user');
                // If refresh token is expired, logout
                await handleLogout(req, res);
              }
              return undefined;
            }
          }
        }

        // logging.debug(settings.authEnv, '[getSession] returning session');

        return sessionPayload;
      } else {
        return undefined;
      }
    } catch (error) {
      logging.debug(settings.authEnv, '[getSession] catch', error);
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  /**
   * The user handler that must be called by the API route that wants to get the user session.
   *
   * It will get the user session and return its claims.
   *
   * If the current accessToken is expired it will try to refresh it with `onRefresh`.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {HandleUserOptions} options The method options if any
   * @returns The current user session in the server
   */
  const handleUser = async (req: NextApiRequest, res: NextApiResponse, options?: HandleUserOptions) => {
    try {
      if (!req) {
        throw new Error('Request is not available');
      }

      if (!res) {
        throw new Error('Response is not available');
      }

      // Get the current session
      const sessionPayload = await getSession(req, res, { ...options });

      logging.debug(settings.authEnv, '[handleUser] validating session');

      // If we have a session, continue
      if (sessionPayload && isSessionValid(sessionPayload)) {
        logging.debug(settings.authEnv, '[handleUser] session is valid');
        logging.debug(settings.authEnv, '[handleLogin] returning public session');
        return { user: sessionPayload.user, accessToken: sessionPayload.accessToken };
      } else {
        logging.debug(settings.authEnv, '[handleUser] session is NOT valid');
        throw await makeDevUnauthorizedError('[handleUser] Invalid session payload');
      }
    } catch (error) {
      logging.debug(settings.authEnv, '[handleUser] catch', error);
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  /**
   * The update handler that must be called by the API route that wants to update the user claims.
   *
   * It will filter the claims and save update the current claims with the existing claims
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns The current user session in the server
   */
  const handleUpdateClaims = async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      if (!req) {
        throw new Error('Request is not available');
      }

      if (!res) {
        throw new Error('Response is not available');
      }

      const allowedOrigins = (await settings.authEnv()).ALLOWED_ORIGINS;

      if (!isOriginAllowed(allowedOrigins, req.headers.origin)) {
        throw await makeDevUnauthorizedError('Origin not allowed');
      }

      // Get the current session
      const sessionPayload = await getSession(req, res, { skipRefresh: true });

      logging.debug(settings.authEnv, '[handleUpdateClaims] validating session');

      // If we have a session, continue
      if (sessionPayload && isSessionValid(sessionPayload) && req.body && Object.keys(req.body).length > 0) {
        logging.debug(settings.authEnv, '[handleUpdateClaims] session is valid');

        // Filters the fields we just got. We can only update simple custom claims
        const bodySession = getSessionFromTokenSet({ claims: req.body } as TokenSet);

        // Makes a new session that merges both
        const finalSession = {
          ...sessionPayload,
          ...bodySession,
          user: { ...sessionPayload.user, ...bodySession.user }
        };

        logging.debug(settings.authEnv, '[handleUpdateClaims] saving merged session payload');

        // Update the current session with the existing + the
        await sessionStore.save(req, res, finalSession);

        logging.debug(settings.authEnv, '[handleUpdateClaims] returning public session');

        return { user: finalSession.user, accessToken: finalSession.accessToken };
      } else {
        logging.debug(settings.authEnv, '[handleUpdateClaims] session is NOT valid');
        throw await makeDevUnauthorizedError('[handleUpdateClaims] Invalid session payload');
      }
    } catch (error) {
      logging.debug(settings.authEnv, '[handleUpdateClaims] catch', error);
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  return {
    /**
     * The handleSignup method can only be used when you are not using the OAuth flow
     */
    handleSignup: () => {
      throw new Error('The handleSignup method can only be used when you are not using the OAuth flow');
    },
    handleLogin,
    handleCallback,
    handleLogout,
    handleUser,
    getSession,
    handleUpdateClaims
  };
};
