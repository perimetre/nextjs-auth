/* eslint-disable @typescript-eslint/no-explicit-any */
import jwt from 'jsonwebtoken';
import logging from './logging';
import util from 'util';
import { AuthSettings } from '.';
import passport from 'passport';
import OAuth2Strategy from 'passport-oauth2';
import refresh from 'passport-oauth2-refresh';
import { NextApiRequest, NextApiResponse } from 'next';
import { UserAuth } from 'service';
import { AuthorizationParameters } from 'serviceOauth';

/**
 * Returns whether or not the given token is expired
 *
 * @param {string} token The token to be checked against
 * @returns {boolean} whether or not the given token is expired
 */
export const isTokenExpired = (token?: string) => {
  if (!token) {
    return true;
  }

  const payload = jwt.decode(token) as { exp?: number | null } | undefined | null;
  return !payload || !payload.exp || Date.now() >= payload.exp * 1000;
};

/**
 * Returns whether or not the given origin is allowed.
 *
 * @param {string} allowedOriginsEnv The ALLOWED_ORIGINS environment string
 * @param {string} origin The current request origin
 * @returns {boolean} whether or not the given origin is allowed.
 */
export const isOriginAllowed = (allowedOriginsEnv?: string, origin?: string): boolean => {
  if (process.env.NODE_ENV !== 'development' && allowedOriginsEnv) {
    if (origin) {
      // Parse the ALLOWED_ORIGINS value
      const allowedOrigins = allowedOriginsEnv.split('|').map((uri) => new URL(uri));

      // If there is some result
      if (allowedOrigins && allowedOrigins.length > 0) {
        const originUrl = new URL(origin);

        // If the given originUrl.host exist in the list of allowed origins
        return allowedOrigins.some((origin) => origin.host === originUrl.host);
      } else {
        // If array is empty, env doesn't have origins, so all are allowed
        return true;
      }
    } else {
      return false;
    }
  } else {
    // If no environment is set, all origins are allowed
    // Or if development is true
    return true;
  }
};

/**
 * @typedef OAuth2Client
 */
export type OAuth2Client = {
  authorize: (req: NextApiRequest, res: NextApiResponse, additionalParams: AuthorizationParameters) => void;
  authenticate: (req: NextApiRequest, res: NextApiResponse) => Promise<{ accessToken: string; refreshToken: string }>;
  refresh: (refreshToken: string) => Promise<{ accessToken?: string; refreshToken?: string }>;
};

/**
 * Returns a OAuth2 client to take care of communicating with authorization server
 *
 * @param {AuthSettings} settings The settings to establish connection with OAuth2 authorization server
 * @returns {OAuth2Client} The OAuth2 client
 */
export const getClient = (settings: AuthSettings): (() => OAuth2Client) => {
  let client: OAuth2Client | undefined = undefined;

  return () => {
    if (client) return client;
    else {
      if (!settings.oauthSettings) {
        throw new Error('oauthSettings property was not provided');
      }
      const strategy = new OAuth2Strategy(
        {
          authorizationURL: settings.oauthSettings.authorizationEndpoint,
          tokenURL: settings.oauthSettings.tokenEndpoint,
          clientID: settings.oauthSettings.clientId,
          clientSecret: settings.oauthSettings.clientSecret,
          callbackURL: settings.oauthSettings.redirectUri
        },
        function (accessToken: string, refreshToken: string, _profile: any, cb: (arg0: any, arg1: UserAuth) => void) {
          logging.debug(settings.authEnv, '[OAuth2Strategy] verify accessToken', accessToken);
          cb(null, { accessToken, refreshToken });
        }
      );
      passport.use('OAuth2Strategy', strategy);
      refresh.use('OAuth2Strategy', strategy);

      /**
       * Authorization redirect method
       *
       * @param {NextApiRequest} req The server request
       * @param {NextApiResponse} res The server response
       * @param {AuthorizationParameters} additionalParams The original options
       */
      const authorizeRedirect = (
        req: NextApiRequest,
        res: NextApiResponse,
        additionalParams: AuthorizationParameters
      ) => {
        passport.authenticate('OAuth2Strategy', additionalParams)(req, res);
      };

      const authenticatePromise = util.promisify(
        (req: NextApiRequest, res: NextApiResponse, cb: (err: any, result: UserAuth) => void) =>
          passport.authenticate('OAuth2Strategy', { failureRedirect: '/login' }, (err: any, result: UserAuth) =>
            cb(err, result)
          )(req, res)
      );

      const refreshPromise = util.promisify((refreshToken: string, cb: (err: any, result: UserAuth) => void) =>
        refresh.requestNewAccessToken('OAuth2Strategy', refreshToken, (err: any, ...results: string[]) =>
          cb(err, { accessToken: results[0], refreshToken: results[1] })
        )
      );

      client = {
        authorize: authorizeRedirect,
        authenticate: authenticatePromise,
        refresh: refreshPromise
      };

      return client;
    }
  };
};
