import CookieSessionStore from '@auth0/nextjs-auth0/dist/session/cookie-store';
import CookieSessionStoreSettings, {
  ICookieSessionStoreSettings
} from '@auth0/nextjs-auth0/dist/session/cookie-store/settings';
import { ISession } from '@auth0/nextjs-auth0/dist/session/session';
import { ISessionStore } from '@auth0/nextjs-auth0/dist/session/store';
import { NextApiRequest, NextApiResponse } from 'next';
import { authService, UserAuth } from './service';

export type AuthEnv = { allowedOrigins?: string; NODE_ENV?: string };

export type AuthSettings = {
  session: ICookieSessionStoreSettings;

  onLogin: (req: NextApiRequest, res: NextApiResponse) => Promise<UserAuth>;
  onSignup: (req: NextApiRequest, res: NextApiResponse) => Promise<UserAuth>;
  onLogout: (req: NextApiRequest, res: NextApiResponse, session: ISession) => Promise<void>;
  onRefresh: (
    req: NextApiRequest,
    res: NextApiResponse,
    refreshToken: string
  ) => Promise<Omit<UserAuth, 'refreshToken'>>;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  formatError?: (err: Error | any) => Error | any;

  authEnv: () => Promise<AuthEnv>;
};

export type AuthClient = {
  isBrowser: boolean;
  handleSignup: ReturnType<typeof authService>['handleSignup'];
  handleLogin: ReturnType<typeof authService>['handleLogin'];
  handleLogout: ReturnType<typeof authService>['handleLogout'];
  handleUser: ReturnType<typeof authService>['handleUser'];
  getSession: ReturnType<typeof authService>['getSession'];
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const createBrowserClient = (settings: AuthSettings): AuthClient => {
  // Ref: https://github.com/auth0/nextjs-auth0/blob/master/src/instance.browser.ts

  // Create guard functions if the client is ever called in the client
  const client: AuthClient = {
    isBrowser: true,
    handleSignup: () => {
      throw new Error('The handleSignup method can only be used from the server side');
    },
    handleLogin: () => {
      throw new Error('The handleLogin method can only be used from the server side');
    },
    handleLogout: () => {
      throw new Error('The handleLogout method can only be used from the server side');
    },
    handleUser: () => {
      throw new Error('The handleUser method can only be used from the server side');
    },
    getSession: () => {
      throw new Error('The getSession method can only be used from the server side');
    }
  };
  return client;
};

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

export const initAuthClient = (settings: AuthSettings): AuthClient => {
  // Ref: https://github.com/auth0/nextjs-auth0/blob/master/src/index.ts
  const isBrowser = typeof window !== 'undefined' || process.browser;
  if (isBrowser) {
    return createBrowserClient(settings);
  }

  return createServerClient(settings);
};
