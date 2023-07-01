import { describe, expect, it, vi } from "vitest";
import { hashPassword, verifyPassword } from "../src/utils/password";
import { badStringParams, passwords } from "./utils.spec";
import { EffyCryptoError } from "../src/errors/effy-crypto-error";
/**
 * @hashPassword and
 * @verifyPassword integration testing
 */

describe("hash & verify password", () => {
  it("with good password", async () => {
    for (let password of passwords) {
      const hashedPassword = await hashPassword(password);
      const isValid = await verifyPassword({ hashedPassword, password });

      expect(isValid).toBe(true);
    }
  });

  it("with bad password", async () => {
    const password = "MyGoodPassword";
    const hashedPassword = await hashPassword(password);

    for (let badPassword of passwords) {
      const isValid = await verifyPassword({
        hashedPassword,
        password: badPassword,
      });

      expect(isValid).toBe(false);
    }
  });
});

/**
 * @hashPassword function testing
 */

describe("hashPassword", () => {
  it("with bad params", async () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;

      try {
        await hashPassword(badParamAsString);
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("password must be a string");
        }
      }
    }
  });

  it("with undefined params", async () => {
    const undefinedParamAsString = undefined as any as string;

    try {
      await hashPassword(undefinedParamAsString);
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const { message } = error.zodErrors[0];

        expect(message).toBe("Required");
      }
    }
  });
});

/**
 * @verifyPassword function testing
 */

describe("verifyPassword", async () => {
  const password = "myTestPaswword";
  const hashedPassword = await hashPassword(password);

  it("with bad params", async () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;

      try {
        await verifyPassword({ hashedPassword: badParamAsString, password });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("hashedPassword must be a string");
        }
      }

      try {
        await verifyPassword({ hashedPassword, password: badParamAsString });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("password must be a string");
        }
      }

      try {
        await verifyPassword({
          hashedPassword: badParamAsString,
          password: badParamAsString,
        });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const [badhash, badPwd] = error.zodErrors.map(
            ({ message }) => message
          );

          expect(badhash).toBe("hashedPassword must be a string");
          expect(badPwd).toBe("password must be a string");
        }
      }
    }
  });

  it("with undefined params", async () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;

    try {
      await verifyPassword({
        hashedPassword: undefinedParamAsString,
        password,
      });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        issues = [...issues, error.zodErrors[0].message];
      }
    }

    try {
      await verifyPassword({
        hashedPassword,
        password: undefinedParamAsString,
      });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        issues = [...issues, error.zodErrors[0].message];
      }
    }

    try {
      await verifyPassword({
        hashedPassword: undefinedParamAsString,
        password: undefinedParamAsString,
      });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const [badhash, badPwd] = error.zodErrors.map(({ message }) => message);
        issues = [...issues, badhash, badPwd];
      }
    }

    issues.forEach((message) => expect(message).toBe("Required"));
  });
});
