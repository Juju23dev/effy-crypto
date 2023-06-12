import jwt from "jsonwebtoken";
import {
  createAuthAndRefreshTokenValidator,
  createTokenTypeValidator,
  jwtPayloadSchema,
  refreshingTokenValidator,
} from "./zod.validators";

const createTokenTool = <T>(secretString: string, expiresIn: string) => {
  createTokenTypeValidator([secretString, expiresIn]);

  return {
    sign: (payload: T | undefined = undefined) =>
      jwt.sign({ data: payload }, secretString, { expiresIn }),
    verify: (token: string) =>
      jwtPayloadSchema.parse(jwt.verify(token, secretString)),
  };
};

type TokenTools = ReturnType<typeof createTokenTool>;

const createAuthAndRefreshToken = (payload: {
  authSecretString: string;
  authExpireIn: string;
  refreshSecretString: string;
  refreshExpireIn: string;
}) => {
  const {
    authSecretString,
    authExpireIn,
    refreshSecretString,
    refreshExpireIn,
  } = createAuthAndRefreshTokenValidator(payload);

  return {
    auth: createTokenTool(authSecretString, authExpireIn),
    refresh: createTokenTool(refreshSecretString, refreshExpireIn),
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

const refreshingToken = <T>(payload: {
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

export { createTokenTool, refreshingToken, createAuthAndRefreshToken };
