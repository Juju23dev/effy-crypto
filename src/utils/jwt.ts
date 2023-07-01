import jwt from 'jsonwebtoken';
import { syncFnErrorCatcher, syncFnSafeErrorCatcher } from '../errors/wrap-fn-error';
import {
  createAuthAndRefreshTokenValidator,
  createTokenTypeValidator,
  jwtPayloadSchema,
  refreshingTokenValidator,
} from './zod.validators';

const createTokenToolFn = <T>(params: { secretString: string; expiresIn: string }) => {
  const { secretString, expiresIn } = createTokenTypeValidator(params);

  return {
    sign: (payload: T | undefined = undefined) =>
      jwt.sign({ data: payload }, secretString, { expiresIn }),
    verify: (token: string) => jwtPayloadSchema.parse(jwt.verify(token, secretString)),
  };
};

type TokenTools = ReturnType<typeof createTokenToolFn>;

const createAuthAndRefreshTokenFn = (payload: {
  authSecretString: string;
  authExpireIn: string;
  refreshSecretString: string;
  refreshExpireIn: string;
}) => {
  const { authSecretString, authExpireIn, refreshSecretString, refreshExpireIn } =
    createAuthAndRefreshTokenValidator(payload);

  return {
    auth: createTokenToolFn({ secretString: authSecretString, expiresIn: authExpireIn }),
    refresh: createTokenToolFn({ secretString: refreshSecretString, expiresIn: refreshExpireIn }),
  };
};

type RefeshingTokenReturn =
  | {
      isJwtValid: true;
      token: string;
    }
  | {
      isJwtValid: false;
      error: unknown;
    };

const refreshingTokenFn = <T>(payload: {
  refreshTokenTools: TokenTools;
  authTokenTools: TokenTools;
  refreshToken: string;
  authTokenPayload: T;
}): RefeshingTokenReturn => {
  const { refreshTokenTools, authTokenTools, refreshToken, authTokenPayload } =
    refreshingTokenValidator(payload);

  try {
    refreshTokenTools.verify(refreshToken);

    return { isJwtValid: true, token: authTokenTools.sign(authTokenPayload) };
  } catch (error) {
    return { isJwtValid: false, error };
  }
};

export const {
  createTokenTool,
  safeCreateTokenTool,
  refreshingToken,
  safeRefreshingToken,
  createAuthAndRefreshToken,
  safeCreateAuthAndRefreshToken,
} = {
  createTokenTool: syncFnErrorCatcher(createTokenToolFn),
  safeCreateTokenTool: syncFnSafeErrorCatcher(createTokenToolFn),
  refreshingToken: syncFnErrorCatcher(refreshingTokenFn),
  safeRefreshingToken: syncFnSafeErrorCatcher(refreshingTokenFn),
  createAuthAndRefreshToken: syncFnErrorCatcher(createAuthAndRefreshTokenFn),
  safeCreateAuthAndRefreshToken: syncFnSafeErrorCatcher(createAuthAndRefreshTokenFn),
};
