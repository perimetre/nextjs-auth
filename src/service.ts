import { ISession } from '@auth0/nextjs-auth0/dist/session/session';
import { ISessionStore } from '@auth0/nextjs-auth0/dist/session/store';
import jwt from 'jsonwebtoken';
import { NextApiRequest, NextApiResponse } from 'next';
import { AuthSettings } from './index';
import { isOriginAllowed, isTokenExpired } from './utils';

export type UserAuth = {
  accessToken: string;
  refreshToken: string;
};

export type HandleUserOptions = {
  skipRefresh?: boolean;
  forceRefresh?: boolean;
};

export type HandleSessionOptions = {
  skipRefresh?: boolean;
  forceRefresh?: boolean;
};

export const authService = (settings: AuthSettings, sessionStore: ISessionStore) => {
  const makeDevUnauthorizedError = async (message: string) =>
    (await settings.authEnv()).NODE_ENV === 'development' ? new Error(message) : new Error('Unauthorized');

  const getSessionFromAuth = (auth: UserAuth): ISession => {
    const { accessToken, refreshToken } = auth;
    const payload = jwt.decode(accessToken);

    if (!payload || typeof payload === 'string') {
      throw new Error('Invalid payload type');
    }

    return { accessToken, refreshToken, user: payload, createdAt: Date.now() };
  };

  const getPublicSession = (session: ISession): ISession => {
    const newSession = { ...session };
    const user = { ...newSession.user };

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

  const isSessionValid = (session?: ISession | null) => session && session.user && Object.keys(session.user).length > 0;

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

      const allowedOrigins = (await settings.authEnv()).allowedOrigins;

      if (!isOriginAllowed(allowedOrigins, req.headers.origin)) {
        throw makeDevUnauthorizedError('Origin not allowed');
      }

      // Call the login callback
      const userAuth = await settings.onSignup(req, res);

      // If we get here we succeeded
      const sessionPayload = getSessionFromAuth(userAuth);

      // Create the session, which will store the user info.
      await sessionStore.save(req, res, sessionPayload);

      const publicSession = getPublicSession(sessionPayload as ISession);
      return { user: publicSession.user, accessToken: publicSession.accessToken };
    } catch (error) {
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

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

      const allowedOrigins = (await settings.authEnv()).allowedOrigins;

      if (!isOriginAllowed(allowedOrigins, req.headers.origin)) {
        throw makeDevUnauthorizedError('Origin not allowed');
      }

      // Call the login callback
      const userAuth = await settings.onLogin(req, res);

      // If we get here we succeeded
      const sessionPayload = getSessionFromAuth(userAuth);

      // Create the session, which will store the user info.
      await sessionStore.save(req, res, sessionPayload);

      const publicSession = getPublicSession(sessionPayload as ISession);
      return { user: publicSession.user, accessToken: publicSession.accessToken };
    } catch (error) {
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  const handleLogout = async (req: NextApiRequest, res: NextApiResponse) => {
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

      // Get the current session
      const sessionPayload = await sessionStore.read(req);

      // If we have a session, continue
      if (isSessionValid(sessionPayload)) {
        try {
          // Call the login callback
          await settings.onLogout(req, res, sessionPayload as ISession);
        } finally {
          await sessionStore.save(req, res, { accessToken: '', refreshToken: '', user: {}, createdAt: Date.now() });
        }
      }

      // If don't have a session just fake that succeded?
    } catch (error) {
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

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

      // Get the current session
      let sessionPayload = await sessionStore.read(req);

      if (isSessionValid(sessionPayload)) {
        sessionPayload = sessionPayload as ISession;

        // If we want to refresh the user
        if (!options?.skipRefresh) {
          if (!settings?.onRefresh) {
            throw new Error('onRefresh callback was not provided');
          }

          if (!sessionPayload.refreshToken) {
            throw new Error('No refresh token available to refetch the profile');
          }

          // If we should force refresh or the token is expired
          if (options?.forceRefresh || isTokenExpired(sessionPayload.accessToken)) {
            // If the refresh is NOT expired
            if (!isTokenExpired(sessionPayload.refreshToken)) {
              // Call the refresh callback
              const userAuth = await settings.onRefresh(req, res, sessionPayload.refreshToken);

              // If we get here we succeeded
              sessionPayload = getSessionFromAuth({
                ...userAuth,
                refreshToken: sessionPayload.refreshToken
              });

              // Create the session, which will store the user info.
              await sessionStore.save(req, res, sessionPayload);
            } else {
              if (isSessionValid(sessionPayload)) {
                // If refresh token is expired, logout
                await handleLogout(req, res);
              }
              return undefined;
            }
          }
        }

        return rawSession ? sessionPayload : getPublicSession(sessionPayload);
      } else {
        return undefined;
      }
    } catch (error) {
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

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

      // If we have a session, continue
      if (isSessionValid(sessionPayload)) {
        const publicSession = getPublicSession(sessionPayload as ISession);
        return { user: publicSession.user, accessToken: publicSession.accessToken };
      } else {
        throw makeDevUnauthorizedError('[handleUser] Invalid session payload');
      }
    } catch (error) {
      // If something failed
      if (settings?.formatError) {
        throw settings?.formatError(error);
      } else {
        throw error;
      }
    }
  };

  return { handleSignup, handleLogin, handleLogout, handleUser, getSession };
};
