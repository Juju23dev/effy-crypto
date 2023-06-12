import { describe, expect, it, vi } from "vitest";
import { hashPassword, verifyPassword } from "../utils/password";
import { ZodError } from "zod";
import { badStringParams, passwords } from "./utils.spec";
/**
 * @hashPassword and
 * @verifyPassword integration testing
 */

describe("hash & verify password", () => {
  it("with good password", async () => {
    for (let password of passwords) {
      const hashedPassword = await hashPassword(password);
      const isValid = await verifyPassword(hashedPassword, password);
      expect(isValid).toBe(true);
    }
  });

  it("with bad password", async () => {
    const password = "MyGoodPassword";
    const hashedPassword = await hashPassword(password);

    for (let badPassword of passwords) {
      const isValid = await verifyPassword(hashedPassword, badPassword);
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
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
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
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        const { message } = error.issues[0];
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
        await verifyPassword(badParamAsString, password);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("hashedPassword must be a string");
        }
      }

      try {
        await verifyPassword(hashedPassword, badParamAsString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("password must be a string");
        }
      }

      try {
        await verifyPassword(badParamAsString, badParamAsString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const [badhash, badPwd] = error.issues.map(({ message }) => message);
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
      await verifyPassword(undefinedParamAsString, password);
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      await verifyPassword(hashedPassword, undefinedParamAsString);
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      await verifyPassword(undefinedParamAsString, undefinedParamAsString);
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        const [badhash, badPwd] = error.issues.map(({ message }) => message);
        issues = [...issues, badhash, badPwd];
      }
    }

    issues.forEach((message) => expect(message).toBe("Required"));
  });
});
