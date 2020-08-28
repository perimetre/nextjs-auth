import jwt from 'jsonwebtoken';

export const isTokenExpired = (token?: string) => {
  if (!token) {
    return true;
  }

  const payload = jwt.decode(token) as { exp?: number | null } | undefined | null;
  return !payload || !payload.exp || Date.now() >= payload.exp * 1000;
};

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
