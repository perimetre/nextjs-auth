import CookieSessionStore from '@auth0/nextjs-auth0/dist/session/cookie-store';
import CookieSessionStoreSettings, {
  ICookieSessionStoreSettings
} from '@auth0/nextjs-auth0/dist/session/cookie-store/settings';
import { ISession } from '@auth0/nextjs-auth0/dist/session/session';
import { ISessionStore } from '@auth0/nextjs-auth0/dist/session/store';
import { NextApiRequest, NextApiResponse } from 'next';
import { authService, UserAuth } from './service';

/**
 * @typedef { import("./service").HandleUserOptions } HandleUserOptions
 * @typedef { import("./service").HandleSessionOptions } HandleSessionOptions
 */

/**
 * @typedef AuthEnv
 */
export type AuthEnv = {
  /**
   * Your current NODE_ENV setting. Used to display detailed errors if is === "developent"
   */
  NODE_ENV?: string;

  /**
   * A list of the allowed origins, split by the '|' operator
   */
  ALLOWED_ORIGINS?: string;
};

/**
 * @typedef AuthSettings
 */
export type AuthSettings = {
  /**
   * Your session settings. Refer to the `session` property of here: https://github.com/auth0/nextjs-auth0#runtime-configuration
   */
  session: ICookieSessionStoreSettings;

  /**
   * An async `onLogin` handler callback, which will be called by the service when `handleLogin` is executing.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns {UserAuth} The user access token and refresh token
   */
  onLogin: (req: NextApiRequest, res: NextApiResponse) => Promise<UserAuth>;

  /**
   * An async `onSignup` handler callback, which will be called by the service when `handleSignup` is executing.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns {UserAuth} The user access token and refresh token
   */
  onSignup: (req: NextApiRequest, res: NextApiResponse) => Promise<UserAuth>;

  /**
   * An async `onLogout` handler callback, which will be called by the service when `handleLogout` is executing.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {ISession} session The current logged user session
   */
  onLogout: (req: NextApiRequest, res: NextApiResponse, session: ISession) => Promise<void>;

  /**
   * An async `onRefresh` handler callback, which will be called by the service when `getSession` is executing and the current user is invalid.
   *
   * It is what's used to update the user's access token using its refresh token
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @param {string} refreshToken The current logged user refresh token
   * @returns The user's access token
   */
  onRefresh: (
    req: NextApiRequest,
    res: NextApiResponse,
    refreshToken: string
  ) => Promise<Omit<UserAuth, 'refreshToken'>>;

  /**
   * A callback that is called every time an error is thrown. Will override the thrown error with what this function returns and throw it instead.
   *
   * @param {Error | any} err The thrown error
   * @returns {Error | any} The formatted error
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  formatError?: (err: Error | any) => Error | any;

  /**
   * An async function used to fetch the environment for the service
   *
   * @returns {AuthEnv} The environment
   */
  authEnv: () => Promise<AuthEnv>;
};

/**
 * @typedef AuthClient
 */
export type AuthClient = {
  /**
   * Whether or not this is a client side context or not.
   */
  isBrowser: boolean;
  /**
   * The signup handler that must be called by a signup API route.
   *
   * It will call the `onSignup` callback, then create a server session for the given user, and return the user payload
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns The user signup properties
   */
  handleSignup: ReturnType<typeof authService>['handleSignup'];
  /**
   * The login handler that must be called by a login API route.
   *
   * It will call the `onLogin` callback, then create a server session for the given user, and return the user payload
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns The user login properties
   */
  handleLogin: ReturnType<typeof authService>['handleLogin'];
  /**
   * The logout handler that must be called by a logout API route.
   *
   * It will call the `onLogout` callback, then clear the server session for the given user.
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   */
  handleLogout: ReturnType<typeof authService>['handleLogout'];
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
  handleUser: ReturnType<typeof authService>['handleUser'];
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
  getSession: ReturnType<typeof authService>['getSession'];

  /**
   * The update handler that must be called by the API route that wants to update the user claims.
   *
   * It will filter the claims and save update the current claims with the existing claims
   *
   * @param {NextApiRequest} req The server request
   * @param {NextApiResponse} res The server response
   * @returns The current user session in the server
   */
  handleUpdateClaims: ReturnType<typeof authService>['handleUpdateClaims'];
};

/**
 * Creates and returns an instance of the auth client to be used in the client side context
 *
 * @param {AuthSettings} _settings The required client settings
 * @returns {AuthClient} An instance of the auth client
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const createBrowserClient = (_settings: AuthSettings): AuthClient => {
  // Ref: https://github.com/auth0/nextjs-auth0/blob/master/src/instance.browser.ts

  // Create guard functions if the client is ever called in the client
  const client: AuthClient = {
    isBrowser: true,
    /**
     * The handleSignup method can only be used from the server side
     */
    handleSignup: () => {
      throw new Error('The handleSignup method can only be used from the server side');
    },
    /**
     * The handleLogin method can only be used from the server side
     */
    handleLogin: () => {
      throw new Error('The handleLogin method can only be used from the server side');
    },
    /**
     * The handleLogout method can only be used from the server side
     */
    handleLogout: () => {
      throw new Error('The handleLogout method can only be used from the server side');
    },
    /**
     * The handleUser method can only be used from the server side
     */
    handleUser: () => {
      throw new Error('The handleUser method can only be used from the server side');
    },
    /**
     * The getSession method can only be used from the server side
     */
    getSession: () => {
      throw new Error('The getSession method can only be used from the server side');
    },
    /**
     * The handleUpdateClaims method can only be used from the server side
     */
    handleUpdateClaims: () => {
      throw new Error('The handleUpdateClaims method can only be used from the server side');
    }
  };
  return client;
};

/**
 * Creates and returns an instance of the auth client to be used in the server side context
 *
 * @param {AuthSettings} settings The required client settings
 * @returns {AuthClient} An instance of the auth client
 */
const createServerClient = (settings: AuthSettings): AuthClient => {
  // Initialize dependencies
  const sessionSettings = new CookieSessionStoreSettings(settings.session);
  const store: ISessionStore = new CookieSessionStore(sessionSettings);
  const service = authService(settings, store);

  // Return client
  const client: AuthClient = {
    isBrowser: false,
    ...service
  };
  return client;
};

/**
 * Creates and returns an instance of the auth client
 *
 * @param {AuthSettings} settings The required client settings
 * @returns {AuthClient} An instance of the auth client
 */
export const initAuthClient = (settings: AuthSettings): AuthClient => {
  // Ref: https://github.com/auth0/nextjs-auth0/blob/master/src/index.ts
  const isBrowser = typeof window !== 'undefined' || process.browser;
  if (isBrowser) {
    return createBrowserClient(settings);
  }

  return createServerClient(settings);
};
