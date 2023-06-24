import { describe, expect, it, vi } from "vitest";
import {
  decryptData,
  encryptData,
  getSecretKey,
  changeSecretKey,
} from "../src/utils/encrypt";
import { ZodError } from "zod";
import { SHA512 } from "crypto-js";
import {
  badStringParams,
  badObjectParams,
  passwords,
  fakeObject,
  randomStrings,
} from "./utils.spec";

/**
 * @encryptData and
 * @decryptData integration testing
 */

describe("encrypt & decrypt data", () => {
  it("with good password", () => {
    for (let password of passwords) {
      const encryptedData = encryptData(fakeObject, password);
      const dataDecrypted = decryptData(encryptedData, password);
      expect(dataDecrypted).toEqual(fakeObject);
    }
  });

  it("with bad password", () => {
    const password = "MyGoodPassword";
    const encryptedData = encryptData(fakeObject, password);
    let errCount = 0;
    for (let badPassword of passwords) {
      try {
        decryptData(encryptedData, badPassword);
      } catch {
        errCount++;
      }
    }
    expect(errCount).toEqual(passwords.length);
  });
});

/**
 * @encryptData function testing
 */

describe("encryptData", () => {
  const password = "myTestPaswword";

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;
      const badParamAsObject = badParam as any as object;

      try {
        encryptData(fakeObject, badParamAsString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("secretKey must be a string");
        }
      }
    }

    for (let badParam of badObjectParams) {
      const badParamAsObject = badParam as any as object;
      try {
        encryptData(badParamAsObject, password);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toMatch(/Expected object, received/);
        }
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;
    const undefinedParamAsObject = undefined as any as object;

    try {
      encryptData(undefinedParamAsObject, password);
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      encryptData(fakeObject, undefinedParamAsString);
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      encryptData(undefinedParamAsObject, undefinedParamAsString);
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

/**
 * @decrytData function testing
 */

describe("decryptData", () => {
  const password = "myTestPaswword";
  const encryptedData = encryptData(fakeObject, password);

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;
      try {
        decryptData(encryptedData, badParamAsString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("secretKey must be a string");
        }
      }

      try {
        decryptData(badParamAsString, password);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toMatch("encryptedData must be a string");
        }
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;

    try {
      decryptData(undefinedParamAsString, password);
    } catch (error) {
      const isZodError = error instanceof ZodError;
      expect(isZodError).toBe(true);

      if (isZodError) {
        issues = [...issues, error.issues[0].message];
      }
    }

    try {
      decryptData(encryptedData, undefinedParamAsString);
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
 * @getSecretKey function testing
 */

describe("getSecretKey", () => {
  it("should hash in SHA512", () => {
    for (let string of randomStrings) {
      const key = getSecretKey(string);
      expect(SHA512(string).toString()).toEqual(key);
    }
  });

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;
      try {
        getSecretKey(badParamAsString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("keyString must be a string");
        }
      }
    }
  });

  it("with undefined params", () => {
    const undefinedParamAsString = undefined as any as string;
    try {
      getSecretKey(undefinedParamAsString);
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
 * @changeSecretKey function testing
 */

describe("changeSecretKey", () => {
  it("changeSecretkey encryption", () => {
    let encryptedData: string | undefined;
    for (let pwdIndex in passwords) {
      const beforePassword = passwords[Number(pwdIndex) - 1];
      const password = passwords[pwdIndex];
      if (!encryptedData) {
        encryptedData = encryptData(fakeObject, passwords[pwdIndex]);
        expect(typeof encryptedData).toBe("string");
      } else {
        encryptedData = changeSecretKey(
          beforePassword,
          password,
          encryptedData
        );
        expect(decryptData(encryptedData, password)).toEqual(fakeObject);

        let cantDecryptWithOldPass = true;
        try {
          const decryptWillFail = decryptData(encryptedData, beforePassword);
          cantDecryptWithOldPass = !decryptWillFail;
        } catch {}

        expect(cantDecryptWithOldPass).toBe(true);
      }
    }
  });

  it("with bad params", () => {
    const goodString = "GoodStringCanBeUseToPassZod";

    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;
      try {
        changeSecretKey(badParamAsString, goodString, goodString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("oldKey must be a string");
        }
      }

      try {
        changeSecretKey(goodString, badParamAsString, goodString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("newKey must be a string");
        }
      }

      try {
        changeSecretKey(goodString, goodString, badParamAsString);
      } catch (error) {
        const isZodError = error instanceof ZodError;
        expect(isZodError).toBe(true);

        if (isZodError) {
          const { message } = error.issues[0];
          expect(message).toBe("encryptedData must be a string");
        }
      }
    }
  });
});
