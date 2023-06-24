import { JsonWebTokenError } from "jsonwebtoken";
import { describe, expect, it, vi } from "vitest";
import { z, ZodError } from "zod";
import {
  refreshingToken,
  createAuthAndRefreshToken,
  createTokenTool,
} from "../src/utils/jwt";
import { tokenToolsShema } from "../src/utils/zod.validators";
import { badStringParams, fakeObject } from "./utils.spec";

/**
 * @createTokenTools function testing
 */

describe("create TokenType", () => {
  const instantExpiration = "0h";
  const secretKey = "secret";

  it("should return a valid TokenTool", () => {
    const tokenTool = createTokenTool(secretKey, "1h");
    expect(tokenToolsShema.safeParse(tokenTool).success).toBe(true);

    const jwt = tokenTool.sign(fakeObject);
    expect(typeof jwt).toBe("string");

    const jwtDecode = tokenTool.verify(jwt);
    expect(jwtDecode.data).toEqual(fakeObject);
  });

  it("create a wrong TokenTools", () => {
    const tokenTool = createTokenTool(secretKey, instantExpiration);
    expect(tokenToolsShema.safeParse(tokenTool).success).toBe(true);

    const jwt = tokenTool.sign(fakeObject);
    expect(typeof jwt).toBe("string");

    let jwtHasFailed = false;
    try {
      const jwtDecode = tokenTool.verify(jwt);
    } catch {
      jwtHasFailed = true;
    }

    expect(jwtHasFailed).toBe(true);
  });

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;

      try {
        createTokenTool(badParamAsString, "1h");
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("secretString must be a string");
        }
      }

      try {
        createTokenTool("secret", badParamAsString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("expiresIn must be a string");
        }
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;
    try {
      createTokenTool(undefinedParamAsString, "1h");
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      createTokenTool("secret", undefinedParamAsString);
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    issues.forEach((message) => expect(message).toBe("Required"));
  });
});

/**
 * @createAuthAndRefreshToken function testing
 */

describe("createAuthAndRefreshToken", () => {
  const config = {
    authExpireIn: "1h",
    authSecretString: "authSecret",
    refreshSecretString: "refreshSecret",
    refreshExpireIn: "24h",
  };

  it("should return two TokenTools", () => {
    const { auth, refresh } = createAuthAndRefreshToken(config);

    expect(tokenToolsShema.safeParse(auth).success).toBe(true);
    expect(tokenToolsShema.safeParse(refresh).success).toBe(true);

    it("auth should be functional", () => {
      const jwt = auth.sign(fakeObject);
      expect(typeof jwt).toBe("string");

      const jwtDecode = auth.verify(jwt);
      expect(jwtDecode.data).toEqual(fakeObject);
    });

    it("refresh should be functional", () => {
      const jwt = refresh.sign(fakeObject);
      expect(typeof jwt).toBe("string");

      const jwtDecode = refresh.verify(jwt);
      expect(jwtDecode.data).toEqual(fakeObject);
    });
  });

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;
      try {
        createAuthAndRefreshToken({
          ...config,
          authExpireIn: badParamAsString,
        });
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("authExpireIn must be a string");
        }
      }

      try {
        createAuthAndRefreshToken({
          ...config,
          authSecretString: badParamAsString,
        });
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("authSecretString must be a string");
        }
      }

      try {
        createAuthAndRefreshToken({
          ...config,
          refreshExpireIn: badParamAsString,
        });
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("refreshExpireIn must be a string");
        }
      }

      try {
        createAuthAndRefreshToken({
          ...config,
          refreshSecretString: badParamAsString,
        });
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("refreshSecretString must be a string");
        }
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;

    try {
      createAuthAndRefreshToken({
        ...config,
        authSecretString: undefinedParamAsString,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      createAuthAndRefreshToken({
        ...config,
        authExpireIn: undefinedParamAsString,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      createAuthAndRefreshToken({
        ...config,
        refreshSecretString: undefinedParamAsString,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      createAuthAndRefreshToken({
        ...config,
        refreshExpireIn: undefinedParamAsString,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    issues.forEach((message) => expect(message).toBe("Required"));
  });
});

/**
 * @refreshing function testing
 */

describe("refreshingToken", () => {
  const config = {
    authExpireIn: "1h",
    authSecretString: "authSecret",
    refreshExpireIn: "24h",
    refreshSecretString: "refreshSecret",
  };
  const { auth, refresh } = createAuthAndRefreshToken(config);

  const refreshingConfig = {
    refreshTokenTools: refresh,
    authTokenTools: auth,
    refreshToken: refresh.sign(),
    authTokenPayload: fakeObject,
  };

  it("should return valid auth jwt", () => {
    const refreshToken = refresh.sign();

    const newAuthToken = refreshingToken({
      refreshTokenTools: refresh,
      authTokenTools: auth,
      refreshToken,
      authTokenPayload: fakeObject,
    });

    expect(newAuthToken.isJwtValid).toBe(true);
    if (newAuthToken.isJwtValid === true) {
      expect(auth.verify(newAuthToken.token).data).toEqual(fakeObject);
    } else {
      throw new Error(" refresh should be valid");
    }
  });

  it("should throwError", () => {
    const { auth: badAuth, refresh: badRefresh } = createAuthAndRefreshToken({
      ...config,
      refreshExpireIn: "0h",
    });

    const refreshToken = badRefresh.sign();

    const invalidRefreshTokenResult = refreshingToken({
      refreshTokenTools: badRefresh,
      authTokenTools: badAuth,
      refreshToken,
      authTokenPayload: fakeObject,
    });

    if (invalidRefreshTokenResult.isJwtValid === false) {
      const { error } = invalidRefreshTokenResult;
      expect(error instanceof JsonWebTokenError).toBe(true);
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;
    const undefinedParamAsTokenTools = undefined as unknown as z.infer<
      typeof tokenToolsShema
    >;

    try {
      refreshingToken({
        ...refreshingConfig,
        refreshTokenTools: undefinedParamAsTokenTools,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      refreshingToken({
        ...refreshingConfig,
        authTokenTools: undefinedParamAsTokenTools,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      refreshingToken({
        ...refreshingConfig,
        refreshToken: undefinedParamAsString,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      refreshingToken({
        ...refreshingConfig,
        authTokenPayload: undefinedParamAsString,
      });
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }
    issues.forEach((message) => expect(message).toBe("Required"));
  });

  it("with wrong params", () => {
    for (let badParam of badStringParams) {
      const badParamAsTokenTools = badParam as unknown as z.infer<
        typeof tokenToolsShema
      >;
      const badParamAsString = badParam as unknown as string;

      try {
        refreshingToken({
          ...refreshingConfig,
          refreshTokenTools: badParamAsTokenTools,
        });
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);
      }

      try {
        refreshingToken({
          ...refreshingConfig,
          refreshToken: badParamAsString,
        });
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);
      }

      try {
        refreshingToken({
          ...refreshingConfig,
          authTokenPayload: badParamAsString,
        });
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);
      }
    }
  });
});
