import { z } from "zod";

/**
 * @helper (s) for validator functions
 */

const paramsTypeInvalid = (paramsName: string, type: string) => ({
  invalid_type_error: `${paramsName} must be a ${type}`,
});

/**
 * @password funtions params validator
 */

export const hashPasswordValidator = z.string(
  paramsTypeInvalid("password", "string")
).parse;

export const verifyPasswordValidator = z.tuple([
  z.string(paramsTypeInvalid("hashedPassword", "string")),
  z.string(paramsTypeInvalid("password", "string")),
]).parse;

/**
 * @password funtions params validator
 */

export const encryptDataValidator = z.tuple([
  z.object({}),
  z.string(paramsTypeInvalid("secretKey", "string")),
]).parse;

export const decryptDataValidator = z.tuple([
  z.string(paramsTypeInvalid("encryptedData", "string")),
  z.string(paramsTypeInvalid("secretKey", "string")),
]).parse;

export const changeSecretKeyValidator = z.tuple([
  z.string(paramsTypeInvalid("oldKey", "string")),
  z.string(paramsTypeInvalid("newKey", "string")),
  z.string(paramsTypeInvalid("encryptedData", "string")),
]).parse;

export const getSecretKeyValidator = z.string(
  paramsTypeInvalid("keyString", "string")
).parse;

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

export const createTokenTypeValidator = z.tuple([
  z.string(paramsTypeInvalid("secretString", "string")),
  z.string(paramsTypeInvalid("expiresIn", "string")),
]).parse;

export const createAuthAndRefreshTokenValidator = z.object({
  authSecretString: z.string(paramsTypeInvalid("authSecretString", "string")),
  authExpireIn: z.string(paramsTypeInvalid("authExpireIn", "string")),
  refreshSecretString: z.string(
    paramsTypeInvalid("refreshSecretString", "string")
  ),
  refreshExpireIn: z.string(paramsTypeInvalid("refreshExpireIn", "string")),
}).parse;

export const refreshingTokenValidator = z.object({
  refreshTokenTools: tokenToolsShema,
  authTokenTools: tokenToolsShema,
  refreshToken: z.string(paramsTypeInvalid("refreshToken", "string")),
  authTokenPayload: z.any(),
}).parse;
