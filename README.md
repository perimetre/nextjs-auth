# @perimetre/nextjs-auth

Auth SDK to add secure signup to a Next.js application

> Note: This library is heavily inspired by [@auth0/nextjs-auth0](https://github.com/auth0/nextjs-auth0). And it even call its libraries for the session management. But it is in no way dependent of the Auth0 service. As the sole intent of this package is to use your own service.

[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

## Installation

```sh
npm install @perimetre/nextjs-auth
```

## Getting Started - Runtime Configuration

This library can be used with handler callbacks for each login action, leaving the implementation to the developer.

It also supports handling logins using the OAuth 2.0 Authorization Code Grant type flow. When using the OAuth approach, the library will take care of the process, so the handler callbacks are NOT used.

### Handling the exchange of user credentials for tokens by yourself

```ts
import { initAuthClient } from '@perimetre/nextjs-auth';

export const getAuthClient = () =>
  initAuthClient({
    authEnv: async () => {
      return {
        /* Environment variables */
      };
    },
    /**
     * An async `onLogin` handler callback, which will be called by the service when `handleLogin` is executing.
     *
     * @param req The server request
     * @param res The server response
     * @returns The user access token and refresh token
     */
    onLogin: async (req, res) => {
      // Call whatever API
      return { accessToken: '', refreshToken: '' };
    },
    /**
     * An async `onSignup` handler callback, which will be called by the service when `handleSignup` is executing.
     *
     * @param req The server request
     * @param res The server response
     * @returns The user access token and refresh token
     */
    onSignup: async (req, res) => {
      // Call whatever API
      return { accessToken: '', refreshToken: '' };
    },
    /**
     * An async `onLogout` handler callback, which will be called by the service when `handleLogout` is executing.
     *
     * @param req The server request
     * @param res The server response
     * @param session The current logged user session
     */
    onLogout: async (req, res, session) => {
      // Call whatever API
    },
    /**
     * An async `onRefresh` handler callback, which will be called by the service when `getSession` is executing and the current user is invalid.
     *
     * It is what's used to update the user's access token using its refresh token
     *
     * @param req The server request
     * @param res The server response
     * @param refreshToken The current logged user refresh token
     * @returns The user's access token
     */
    onRefresh: async (req, _res, refreshToken) => {
      // Call whatever API
      return { accessToken: '' };
    },
    /**
     * A callback that is called every time an error is thrown. Will override the thrown error with what this function returns and throw it instead.
     *
     * @param err The thrown error
     * @returns The formatted error
     */
    formatError: (error) => {
      // Format your error
      return new Error(error);
    },
    session: // Refer to the @auth0/nextjs-auth0 runtime configuration at https://github.com/auth0/nextjs-auth0#runtime-configuration
  });
```

### Handling authentication with the OAuth 2.0 Authorization Code Grant

If the property `oauthSettings` is provided, the library will attempt to make logins with the OAuth 2.0 flow. In this case, the callbacks for each login handler are not used so they shouldn't be provided. 

```ts
import { initAuthClient } from '@perimetre/nextjs-auth';

export const getAuthClient = () =>
  initAuthClient({
    authEnv: async () => {
      return {
        /* Environment variables */
      };
    },
    /**
     * OAuth authorization settings. Enables handling OAuth 2 login authorizations, if provided.
     */
    oauthSettings: {
      /**
       * Authorization server authorization endpoint url.
       */
      authorizationEndpoint: '',

      /**
       * Authorization server token endpoint url.
       */
      tokenEndpoint: '',

      /**
       * Your client ID in the authorization server.
       */
      clientId: '',

      /**
       * Your client secret in the authorization server.
       */
      clientSecret: '',

      /**
       * Url to redirect to after the user has signed in at the authorization server.
       */
      redirectUri: '',

      /**
       * The scope requested by the client.
       */
      scope: '',

      /**
       * Optional. The audience identifies the resource server that should accept tokens generated when your client is authorized.
       */
      audience: ''
    },
    session: // Refer to the @auth0/nextjs-auth0 runtime configuration at https://github.com/auth0/nextjs-auth0#runtime-configuration
  });
```

## Cookies

[Refer to @auth0/nextjs-auth0 cookies documentation](https://github.com/auth0/nextjs-auth0#cookies)

## Troubleshooting

[Refer to @auth0/nextjs-auth0 troubleshooting documentation](https://github.com/auth0/nextjs-auth0#troubleshooting)

## License

This project is licensed under the MIT license. See the [LICENSE](https://github.com/perimetre/nextjs-auth/blob/master/LICENSE) file for more info.
