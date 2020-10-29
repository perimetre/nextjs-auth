import CookieSessionStoreSettings from '@auth0/nextjs-auth0/dist/session/cookie-store/settings';
import { ISession } from '@auth0/nextjs-auth0/dist/session/session';
import { ISessionStore } from '@auth0/nextjs-auth0/dist/session/store';
import { setCookies } from '@auth0/nextjs-auth0/dist/utils/cookies';
import jwt from 'jsonwebtoken';
import { NextApiRequest, NextApiResponse } from 'next';
import { AuthSettings } from './index';
import { isOriginAllowed, isTokenExpired } from './utils';
import logging from './logging';

/**
 * @typedef UserAuth
 */
export type UserAuth = {
  /**
   * The user's accessToken
   */
  accessToken: string;
  /**
   * The user's refreshToken
   */
  refreshToken: string;
};

/**
 * @typedef HandleUserOptions
 */
export type HandleUserOptions = {
  /**
   * Whether or not you want to skip the refresh of the token if it ever happens
   */
  skipRefresh?: boolean;

  /**
   * Whether or not you want to force the refresh of the token every time an access token is requested
   */
  forceRefresh?: boolean;
};

/**
 * @typedef HandleSessionOptions
 */
export type HandleSessionOptions = {
  /**
   * Whether or not you want to skip the refresh of the token if it ever happens
   */
  skipRefresh?: boolean;

  /**
   * Whether or not you want to force the refresh of the token every time an access token is requested
   */
  forceRefresh?: boolean;
};

/**
 * @typedef HandleLogoutOptions
 */
export type HandleLogoutOptions = {
  /**
   * Redirect url after user session has been saved.
   */
  redirectTo?: string;

  /**
   * Whether or not the redirect should be skipped at all
   */
  skipRedirect?: boolean;
};

/**
 * Creates an instance of the auth service
 *
 * @param {AuthSettings} settings The settings used for the auth client
 * @param {ISessionStore} sessionStore An instance of the sessionStore to be used
 * @param {CookieSessionStoreSettings} sessionSettings An instance of the sessionStore settings
 * @returns {typeof authService} The authService instance
 */
export const authService = (
  settings: AuthSettings,
  sessionStore: ISessionStore,
  sessionSettings: CookieSessionStoreSettings
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
   * Get the same session but in an filtered object, that can be used publicly and returned from an API and without any OIDC specific claim.
   *
   * @param {ISession} session A non filtered session
   * @returns {ISession} A filtered session
   */
  const getPublicSession = (session: ISession): ISession => {
    const newSession = { ...session };
    const user = { ...newSession.user };

    logging.debug(settings.authEnv, '[getPublicSession] Filtering a session object');

    // Get the claims without any OIDC specific claim.
    if (user.aud) {
      delete user.aud;
    }

    if (user.exp) {
      delete user.exp;
    }

    if (user.iat) {
      delete user.iat;
    }

    if (user.iss) {
      delete user.iss;
    }

    return { ...newSession, user };
  };

  /**
   * Returns whether or not the given session is valid.
   *
   * @param {ISession | null | undefined} session The session
   * @returns {boolean} whether or not the given session is valid.
   */
  const isSessionValid = (session?: ISession | null) => session && session.user && Object.keys(session.user).length > 0;

  /**
   * The signup handler that must be called by a signup API route.
   *
   * It will call the `onSignup` callback, then create a server session for the given user, and return the user payload
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns The user signup properties
   */
  const handleSignup = async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      if (!settings?.onSignup) {
        throw new Error('onSignup callback was not provided');
      }

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

      logging.debug(settings.authEnv, '[handleSignup] Calling onSignup callback');

      // Call the login callback
      const userAuth = await settings.onSignup(req, res);

      logging.debug(settings.authEnv, '[handleSignup] onSignup callback finished successfully');

      // If we get here we succeeded
      const sessionPayload = getSessionFromAuth(userAuth);

      logging.debug(settings.authEnv, '[handleSignup] saving session payload');

      // Create the session, which will store the user info.
      await sessionStore.save(req, res, sessionPayload);

      const publicSession = getPublicSession(sessionPayload as ISession);

      logging.debug(settings.authEnv, '[handleSignup] returning public session');

      return { user: publicSession.user, accessToken: publicSession.accessToken };
    } catch (error) {
      logging.debug(settings.authEnv, '[handleSignup] catch', error);
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  /**
   * The login handler that must be called by a login API route.
   *
   * It will call the `onLogin` callback, then create a server session for the given user, and return the user payload
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns The user login properties
   */
  const handleLogin = async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      if (!settings?.onLogin) {
        throw new Error('onLogin callback was not provided');
      }

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

      logging.debug(settings.authEnv, '[handleLogin] Calling onLogin callback');

      // Call the login callback
      const userAuth = await settings.onLogin(req, res);

      logging.debug(settings.authEnv, '[handleLogin] onLogin callback finished successfully');

      // If we get here we succeeded
      const sessionPayload = getSessionFromAuth(userAuth);

      logging.debug(settings.authEnv, '[handleLogin] saving session payload');

      // Create the session, which will store the user info.
      await sessionStore.save(req, res, sessionPayload);

      const publicSession = getPublicSession(sessionPayload as ISession);

      logging.debug(settings.authEnv, '[handleLogin] returning public session');

      return { user: publicSession.user, accessToken: publicSession.accessToken };
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
   * The logout handler that must be called by a logout API route.
   *
   * It will call the `onLogout` callback, then clear the server session for the given user.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {HandleLogoutOptions} options The method options if any
   */
  const handleLogout = async (req: NextApiRequest, res: NextApiResponse, options?: HandleLogoutOptions) => {
    try {
      if (!settings?.onLogout) {
        throw new Error('onLogout callback was not provided');
      }

      if (!req) {
        throw new Error('Request is not available');
      }

      if (!res) {
        throw new Error('Response is not available');
      }

      const redirectTo = req.query.redirectTo || options?.redirectTo;

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
        try {
          logging.debug(settings.authEnv, '[handleLogout] Calling onLogout callback');

          // Call the login callback
          await settings.onLogout(req, res, sessionPayload as ISession);

          logging.debug(settings.authEnv, '[handleLogout] onLogout callback finished successfully');
        } catch (err) {
          logging.debug(settings.authEnv, '[handleLogout] onLogout callback error', err);
        }

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

      if (!options?.skipRedirect && redirectTo) {
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
   * @param {boolean} rawSession Whether or not should filter the session keys
   * @returns {ISession | undefined} The current user session within the server.
   */
  const getSession = async (
    req: NextApiRequest,
    res: NextApiResponse,
    options?: HandleSessionOptions,
    rawSession?: boolean
  ) => {
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
          if (!settings?.onRefresh) {
            throw new Error('onRefresh callback was not provided');
          }

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

              logging.debug(settings.authEnv, '[getSession] Calling onRefresh callback');

              // Call the refresh callback
              const userAuth = await settings.onRefresh(req, res, sessionPayload.refreshToken);

              logging.debug(settings.authEnv, '[getSession] onRefresh callback finished successfully');

              // If we get here we succeeded
              sessionPayload = getSessionFromAuth({
                refreshToken: sessionPayload.refreshToken,
                ...userAuth
              });

              logging.debug(settings.authEnv, '[getSession] saving new refreshed session payload');

              // Create the session, which will store the user info.
              await sessionStore.save(req, res, sessionPayload);
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

        logging.debug(settings.authEnv, '[getSession] returning public or raw session');

        return rawSession ? sessionPayload : getPublicSession(sessionPayload);
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
      const sessionPayload = await getSession(req, res, { ...options }, true);

      logging.debug(settings.authEnv, '[handleUser] validating session');

      // If we have a session, continue
      if (isSessionValid(sessionPayload)) {
        logging.debug(settings.authEnv, '[handleUser] session is valid');
        const publicSession = getPublicSession(sessionPayload as ISession);
        logging.debug(settings.authEnv, '[handleLogin] returning public session');
        return { user: publicSession.user, accessToken: publicSession.accessToken };
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
      const sessionPayload = await getSession(req, res, { skipRefresh: true }, true);

      logging.debug(settings.authEnv, '[handleUpdateClaims] validating session');

      // If we have a session, continue
      if (sessionPayload && isSessionValid(sessionPayload) && req.body && Object.keys(req.body).length > 0) {
        logging.debug(settings.authEnv, '[handleUpdateClaims] session is valid');

        // Filters the fields we just got. We can only update simple custom claims
        const bodySession = getPublicSession({ user: req.body } as ISession);

        // Makes a new session that merges both
        const finalSession = {
          ...sessionPayload,
          ...bodySession,
          user: { ...sessionPayload.user, ...bodySession.user }
        };

        logging.debug(settings.authEnv, '[handleUpdateClaims] saving merged session payload');

        // Update the current session with the existing + the
        await sessionStore.save(req, res, finalSession);

        const publicSession = getPublicSession(finalSession);

        logging.debug(settings.authEnv, '[handleUpdateClaims] returning public session');

        return { user: publicSession.user, accessToken: publicSession.accessToken };
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
    handleSignup,
    handleLogin,
    /**
     * The handleCallback method can only be used when you are using the OAuth flow
     */
    handleCallback: () => {
      throw new Error('The handleCallback method can only be used when you are using the OAuth flow');
    },
    handleLogout,
    handleUser,
    getSession,
    handleUpdateClaims
  };
};
