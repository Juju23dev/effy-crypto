import { z } from 'zod';

/**
 * @helper (s) for validator functions
 */

const paramsTypeInvalid = (paramsName: string, type: string) => ({
  invalid_type_error: `${paramsName} must be a ${type}`,
});

/**
 * @password funtions params validator
 */

export const hashPasswordValidator = z.string(paramsTypeInvalid('password', 'string')).parse;

export const verifyPasswordValidator = z.object({
  hashedPassword: z.string(paramsTypeInvalid('hashedPassword', 'string')),
  password: z.string(paramsTypeInvalid('password', 'string')),
}).parse;

/**
 * @password funtions params validator
 */

export const encryptDataValidator = z.object({
  data: z.any(),
  secretKey: z.string(paramsTypeInvalid('secretKey', 'string')),
}).parse;

export const decryptDataValidator = z.object({
  encryptedData: z.string(paramsTypeInvalid('encryptedData', 'string')),
  secretKey: z.string(paramsTypeInvalid('secretKey', 'string')),
}).parse;

export const changeSecretKeyValidator = z.object({
  oldKey: z.string(paramsTypeInvalid('oldKey', 'string')),
  newKey: z.string(paramsTypeInvalid('newKey', 'string')),
  encryptedData: z.string(paramsTypeInvalid('encryptedData', 'string')),
}).parse;

export const getSecretKeyValidator = z.string(paramsTypeInvalid('keyString', 'string')).parse;

/**
 * @jwt function params validator
 */
export const jwtPayloadSchema = z.object({
  data: z.any(),
  iat: z.number(),
  exp: z.number(),
});

export const tokenToolsShema = z.object({
  sign: z.function().args(z.any()).returns(z.string()),
  verify: z.function().args(z.string()).returns(jwtPayloadSchema),
});

export const createTokenTypeValidator = z.object({
  secretString: z.string(paramsTypeInvalid('secretString', 'string')),
  expiresIn: z.string(paramsTypeInvalid('expiresIn', 'string')),
}).parse;

export const createAuthAndRefreshTokenValidator = z.object({
  authSecretString: z.string(paramsTypeInvalid('authSecretString', 'string')),
  authExpireIn: z.string(paramsTypeInvalid('authExpireIn', 'string')),
  refreshSecretString: z.string(paramsTypeInvalid('refreshSecretString', 'string')),
  refreshExpireIn: z.string(paramsTypeInvalid('refreshExpireIn', 'string')),
}).parse;

export const refreshingTokenValidator = z.object({
  refreshTokenTools: tokenToolsShema,
  authTokenTools: tokenToolsShema,
  refreshToken: z.string(paramsTypeInvalid('refreshToken', 'string')),
  authTokenPayload: z.any(),
}).parse;
