import { describe, expect, it, vi } from "vitest";
import {
  hashPassword,
  safeHashPassword,
  safeVerifyPassword,
  verifyPassword,
} from "../src/utils/password";
import { badStringParams, passwords } from "./utils.spec";
import { EffyCryptoError } from "../src/errors/effy-crypto-error";
/**
 * @hashPassword and
 * @verifyPassword integration testing
 */

describe("hash & verify password", () => {
  it("with good password", async () => {
    for (let password of passwords) {
      const hashedPassword = await safeHashPassword(password);

      expect(hashedPassword.success).toBe(true);

      if (!hashedPassword.success || !hashedPassword.data) {
        throw new Error("should never happen");
      }

      const isValid = await safeVerifyPassword({
        hashedPassword: hashedPassword.data,
        password,
      });

      expect(isValid.success).toBe(true);

      if (!isValid.success || isValid.data === undefined) {
        throw new Error("should never happen");
      }

      expect(isValid.data).toBe(true);
    }
  });

  it("with bad password", async () => {
    const password = "MyGoodPassword";
    const hashedPassword = await safeHashPassword(password);

    expect(hashedPassword.success).toBe(true);

    if (!hashedPassword.success || !hashedPassword.data) {
      throw new Error("should never happen");
    }

    for (let badPassword of passwords) {
      const isValid = await safeVerifyPassword({
        hashedPassword: hashedPassword.data,
        password: badPassword,
      });

      expect(isValid.success).toBe(true);

      if (!isValid.success || isValid.data === undefined) {
        throw new Error("should never happen");
      }

      expect(isValid.data).toBe(false);
    }
  });
});

/**
 * @safeHashPassword function testing
 */

describe("hashPassword", () => {
  it("with bad params", async () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;

      const data = await safeHashPassword(badParamAsString);
      if (data.success || !data.error) {
        throw new Error("should never happen");
      }

      const { error } = data;
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const { message } = error.zodErrors[0];

        expect(message).toBe("password must be a string");
      }
    }
  });

  it("with undefined params", async () => {
    const undefinedParamAsString = undefined as any as string;

    const data = await safeHashPassword(undefinedParamAsString);
    if (data.success || !data.error) {
      throw new Error("should never happen");
    }

    const { error } = data;
    const isEffyCryptoError = error instanceof EffyCryptoError;

    expect(isEffyCryptoError).toBe(true);

    if (isEffyCryptoError) {
      const { message } = error.zodErrors[0];

      expect(message).toBe("Required");
    }
  });
});

/**
 * @safeVerifyPassword function testing
 */

describe("verifyPassword", async () => {
  const password = "myTestPaswword";
  const hashedPassword = await hashPassword(password);

  it("with bad params", async () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;

      const data = await safeVerifyPassword({
        hashedPassword: badParamAsString,
        password,
      });

      if (data.success || !data.error) {
        throw new Error("should never happen");
      }

      const { error } = data;
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const { message } = error.zodErrors[0];

        expect(message).toBe("hashedPassword must be a string");
      }

      const data2 = await safeVerifyPassword({
        hashedPassword,
        password: badParamAsString,
      });

      if (data2.success || !data2.error) {
        throw new Error("should never happen");
      }

      const { error: error2 } = data2;
      const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

      expect(isEffyCryptoError2).toBe(true);

      if (isEffyCryptoError2) {
        const { message } = error2.zodErrors[0];

        expect(message).toBe("password must be a string");
      }

      const data3 = await safeVerifyPassword({
        hashedPassword: badParamAsString,
        password: badParamAsString,
      });

      if (data3.success || !data3.error) {
        throw new Error("should never happen");
      }

      const { error: error3 } = data3;
      const isEffyCryptoError3 = error3 instanceof EffyCryptoError;

      expect(isEffyCryptoError3).toBe(true);

      if (isEffyCryptoError3) {
        const [badhash, badPwd] = error3.zodErrors.map(
          ({ message }) => message
        );

        expect(badhash).toBe("hashedPassword must be a string");
        expect(badPwd).toBe("password must be a string");
      }
    }
  });

  it("with undefined params", async () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;

    const data = await safeVerifyPassword({
      hashedPassword: undefinedParamAsString,
      password,
    });

    if (data.success || !data.error) {
      throw new Error("should never happen");
    }

    const { error } = data;
    const isEffyCryptoError = error instanceof EffyCryptoError;

    expect(isEffyCryptoError).toBe(true);

    if (isEffyCryptoError) {
      issues = [...issues, error.zodErrors[0].message];
    }

    const data2 = await safeVerifyPassword({
      hashedPassword,
      password: undefinedParamAsString,
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

    const data3 = await safeVerifyPassword({
      hashedPassword: undefinedParamAsString,
      password: undefinedParamAsString,
    });

    expect(data3.success).toBe(false);

    if (data3.success || !data3.error) {
      throw new Error("should never happen");
    }

    const { error: error3 } = data3;
    const isEffyCryptoError3 = error3 instanceof EffyCryptoError;

    expect(isEffyCryptoError3).toBe(true);

    if (isEffyCryptoError3) {
      const [badhash, badPwd] = error3.zodErrors.map(({ message }) => message);
      issues = [...issues, badhash, badPwd];
    }

    issues.forEach((message) => expect(message).toBe("Required"));
  });
});
