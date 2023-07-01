import { JsonWebTokenError } from "jsonwebtoken";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { EffyCryptoError } from "../src/errors/effy-crypto-error";
import {
  createAuthAndRefreshToken,
  safeCreateTokenTool,
  safeCreateAuthAndRefreshToken,
  safeRefreshingToken,
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
    const tokenTool = safeCreateTokenTool({
      secretString: secretKey,
      expiresIn: "1h",
    });

    expect(tokenTool.success).toBe(true);

    if (!tokenTool.success || !tokenTool.data) {
      throw new Error("should never happen");
    }

    expect(tokenToolsShema.safeParse(tokenTool.data).success).toBe(true);

    const jwt = tokenTool.data.sign(fakeObject);

    expect(typeof jwt).toBe("string");

    const jwtDecode = tokenTool.data.verify(jwt);

    expect(jwtDecode.data).toEqual(fakeObject);
  });

  it("create a wrong TokenTools", () => {
    const tokenTool = safeCreateTokenTool({
      secretString: secretKey,
      expiresIn: instantExpiration,
    });

    expect(tokenTool.success).toBe(true);

    if (!tokenTool.success || !tokenTool.data) {
      throw new Error("should never happen");
    }

    expect(tokenToolsShema.safeParse(tokenTool.data).success).toBe(true);

    const jwt = tokenTool.data.sign(fakeObject);
    expect(typeof jwt).toBe("string");

    let jwtHasFailed = false;
    try {
      const jwtDecode = tokenTool.data.verify(jwt);
    } catch {
      jwtHasFailed = true;
    }

    expect(jwtHasFailed).toBe(true);
  });

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;

      const data = safeCreateTokenTool({
        secretString: badParamAsString,
        expiresIn: "1h",
      });
      expect(data.success).toBe(false);

      if (data.success || !data.error) {
        throw new Error("should never happen");
      }

      const { error } = data;
      const isEffyCryptoError = error instanceof EffyCryptoError;
      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const { message } = error.zodErrors[0];
        expect(message).toBe("secretString must be a string");
      }

      const data2 = safeCreateTokenTool({
        secretString: "secret",
        expiresIn: badParamAsString,
      });

      expect(data2.success).toBe(false);

      if (data2.success || !data2.error) {
        throw new Error("should never happen");
      }

      const { error: error2 } = data2;
      const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

      expect(isEffyCryptoError2).toBe(true);

      if (isEffyCryptoError2) {
        const { message } = error2.zodErrors[0];

        expect(message).toBe("expiresIn must be a string");
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;
    const data = safeCreateTokenTool({
      secretString: undefinedParamAsString,
      expiresIn: "1h",
    });

    expect(data.success).toBe(false);

    if (data.success || !data.error) {
      throw new Error("should never happen");
    }

    const { error } = data;
    const isEffyCryptoError = error instanceof EffyCryptoError;

    expect(isEffyCryptoError).toBe(true);

    if (isEffyCryptoError) {
      issues = [...issues, error.zodErrors[0].message];
    }

    const data2 = safeCreateTokenTool({
      secretString: "secret",
      expiresIn: undefinedParamAsString,
    });

    expect(data2.success).toBe(false);

    if (data2.success || !data2.error) {
      throw new Error("should never happen");
    }

    const { error: error2 } = data2;
    const isEffyCryptoError2 = error2 instanceof EffyCryptoError;
    expect(isEffyCryptoError2).toBe(true);

    if (isEffyCryptoError2) {
      issues = [...issues, error2.zodErrors[0].message];
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
    const data = safeCreateAuthAndRefreshToken(config);

    expect(data.success).toBe(true);

    if (!data.success || !data.data) {
      throw new Error("should never happen");
    }

    const { auth, refresh } = data.data;

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
      const data = safeCreateAuthAndRefreshToken({
        ...config,
        authExpireIn: badParamAsString,
      });

      expect(data.success).toBe(false);

      if (data.success || !data.error) {
        throw new Error("should never happen");
      }

      const { error } = data;
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const { message } = error.zodErrors[0];

        expect(message).toBe("authExpireIn must be a string");
      }

      const data2 = safeCreateAuthAndRefreshToken({
        ...config,
        authSecretString: badParamAsString,
      });

      expect(data2.success).toBe(false);

      if (data2.success || !data2.error) {
        throw new Error("should never happen");
      }

      const { error: error2 } = data2;
      const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

      expect(isEffyCryptoError2).toBe(true);

      if (isEffyCryptoError2) {
        const { message } = error2.zodErrors[0];

        expect(message).toBe("authSecretString must be a string");
      }

      const data3 = safeCreateAuthAndRefreshToken({
        ...config,
        refreshExpireIn: badParamAsString,
      });

      expect(data3.success).toBe(false);

      if (data3.success || !data3.error) {
        throw new Error("should never happen");
      }

      const { error: error3 } = data3;
      const isEffyCryptoError3 = error3 instanceof EffyCryptoError;

      expect(isEffyCryptoError3).toBe(true);

      if (isEffyCryptoError3) {
        const { message } = error3.zodErrors[0];

        expect(message).toBe("refreshExpireIn must be a string");
      }

      const data4 = safeCreateAuthAndRefreshToken({
        ...config,
        refreshSecretString: badParamAsString,
      });

      expect(data4.success).toBe(false);

      if (data4.success || !data4.error) {
        throw new Error("should never happen");
      }

      const { error: error4 } = data4;
      const isEffyCryptoError4 = error4 instanceof EffyCryptoError;

      expect(isEffyCryptoError4).toBe(true);

      if (isEffyCryptoError4) {
        const { message } = error4.zodErrors[0];

        expect(message).toBe("refreshSecretString must be a string");
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;

    const data = safeCreateAuthAndRefreshToken({
      ...config,
      authSecretString: undefinedParamAsString,
    });

    expect(data.success).toBe(false);

    if (data.success || !data.error) {
      throw new Error("should never happen");
    }

    const { error } = data;
    const isEffyCryptoError = error instanceof EffyCryptoError;

    expect(isEffyCryptoError).toBe(true);

    if (isEffyCryptoError) {
      issues = [...issues, error.zodErrors[0].message];
    }

    const data2 = safeCreateAuthAndRefreshToken({
      ...config,
      authExpireIn: undefinedParamAsString,
    });

    expect(data2.success).toBe(false);

    if (data2.success || !data2.error) {
      throw new Error("should never happen");
    }

    const { error: error2 } = data2;
    const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

    expect(isEffyCryptoError2).toBe(true);

    if (isEffyCryptoError2) {
      issues = [...issues, error2.zodErrors[0].message];
    }

    const data3 = safeCreateAuthAndRefreshToken({
      ...config,
      refreshSecretString: undefinedParamAsString,
    });

    expect(data3.success).toBe(false);

    if (data3.success || !data3.error) {
      throw new Error("should never happen");
    }

    const { error: error3 } = data3;
    const isEffyCryptoError3 = error3 instanceof EffyCryptoError;

    expect(isEffyCryptoError3).toBe(true);

    if (isEffyCryptoError3) {
      issues = [...issues, error3.zodErrors[0].message];
    }

    const data4 = safeCreateAuthAndRefreshToken({
      ...config,
      refreshExpireIn: undefinedParamAsString,
    });

    expect(data4.success).toBe(false);

    if (data4.success || !data4.error) {
      throw new Error("should never happen");
    }

    const { error: error4 } = data4;
    const isEffyCryptoError4 = error4 instanceof EffyCryptoError;

    expect(isEffyCryptoError4).toBe(true);

    if (isEffyCryptoError4) {
      issues = [...issues, error.zodErrors[0].message];
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

    const newAuthToken = safeRefreshingToken({
      refreshTokenTools: refresh,
      authTokenTools: auth,
      refreshToken,
      authTokenPayload: fakeObject,
    });

    expect(newAuthToken.success).toBe(true);

    if (!newAuthToken.success || !newAuthToken.data) {
      throw new Error("should never happen");
    }

    expect(newAuthToken.data.isJwtValid).toBe(true);

    if (newAuthToken.data.isJwtValid === true) {
      expect(auth.verify(newAuthToken.data.token).data).toEqual(fakeObject);
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

    const invalidRefreshTokenResult = safeRefreshingToken({
      refreshTokenTools: badRefresh,
      authTokenTools: badAuth,
      refreshToken,
      authTokenPayload: fakeObject,
    });

    expect(invalidRefreshTokenResult.success).toBe(true);

    if (!invalidRefreshTokenResult.success || !invalidRefreshTokenResult.data) {
      throw new Error("should never happen");
    }

    if (invalidRefreshTokenResult.data.isJwtValid === false) {
      const { error } = invalidRefreshTokenResult.data;

      expect(error instanceof JsonWebTokenError).toBe(true);
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;
    const undefinedParamAsTokenTools = undefined as unknown as z.infer<
      typeof tokenToolsShema
    >;

    const data = safeRefreshingToken({
      ...refreshingConfig,
      refreshTokenTools: undefinedParamAsTokenTools,
    });

    expect(data.success).toBe(false);

    if (data.success || !data.error) {
      throw new Error("should never happen");
    }

    const { error } = data;
    const isEffyCryptoError = error instanceof EffyCryptoError;

    expect(isEffyCryptoError).toBe(true);

    if (isEffyCryptoError) {
      issues = [...issues, error.zodErrors[0].message];
    }

    const data2 = safeRefreshingToken({
      ...refreshingConfig,
      authTokenTools: undefinedParamAsTokenTools,
    });

    expect(data2.success).toBe(false);

    if (data2.success || !data2.error) {
      throw new Error("should never happen");
    }

    const { error: error2 } = data2;
    const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

    expect(isEffyCryptoError2).toBe(true);

    if (isEffyCryptoError2) {
      issues = [...issues, error2.zodErrors[0].message];
    }

    const data3 = safeRefreshingToken({
      ...refreshingConfig,
      refreshToken: undefinedParamAsString,
    });

    expect(data3.success).toBe(false);

    if (data3.success || !data3.error) {
      throw new Error("should never happen");
    }

    const { error: error3 } = data3;
    const isEffyCryptoError3 = error3 instanceof EffyCryptoError;

    expect(isEffyCryptoError3).toBe(true);

    if (isEffyCryptoError3) {
      issues = [...issues, error3.zodErrors[0].message];
    }

    issues.forEach((message) => expect(message).toBe("Required"));
  });

  it("with wrong params", () => {
    for (let badParam of badStringParams) {
      const badParamAsTokenTools = badParam as unknown as z.infer<
        typeof tokenToolsShema
      >;
      const badParamAsString = badParam as unknown as string;

      const data = safeRefreshingToken({
        ...refreshingConfig,
        refreshTokenTools: badParamAsTokenTools,
      });

      expect(data.success).toBe(false);

      if (data.success || !data.error) {
        throw new Error("should never happen");
      }

      const { error } = data;

      const isEffyCryptoError = error instanceof EffyCryptoError;
      expect(isEffyCryptoError).toBe(true);

      const data2 = safeRefreshingToken({
        ...refreshingConfig,
        refreshToken: badParamAsString,
      });
      expect(data2.success).toBe(false);

      if (data2.success || !data2.error) {
        throw new Error("should never happen");
      }

      const { error: error2 } = data2;
      const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

      expect(isEffyCryptoError2).toBe(true);
    }
  });
});
