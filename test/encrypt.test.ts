import { describe, expect, it } from "vitest";
import {
  decryptData,
  encryptData,
  getSecretKey,
  changeSecretKey,
} from "../src/utils/encrypt";
import { SHA512 } from "crypto-js";
import {
  badStringParams,
  badObjectParams,
  passwords,
  fakeObject,
  randomStrings,
} from "./utils.spec";
import { EffyCryptoError } from "../src/errors/effy-crypto-error";

/**
 * @encryptData and
 * @decryptData integration testing
 */

describe("encrypt & decrypt data", () => {
  it("with good password", () => {
    for (let password of passwords) {
      const encryptedData = encryptData({
        data: fakeObject,
        secretKey: password,
      });
      const dataDecrypted = decryptData({ encryptedData, secretKey: password });

      expect(dataDecrypted).toEqual(fakeObject);
    }
  });

  it("with bad password", () => {
    const password = "MyGoodPassword";
    const encryptedData = encryptData({
      data: fakeObject,
      secretKey: password,
    });
    let errCount = 0;
    for (let badPassword of passwords) {
      try {
        decryptData({ encryptedData, secretKey: badPassword });
      } catch (error) {
        errCount++;

        expect(error instanceof EffyCryptoError).toBe(true);
        expect(error.unknownError).toBeDefined();
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

      try {
        encryptData({ data: fakeObject, secretKey: badParamAsString });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("secretKey must be a string");
        }
      }
    }

    for (let badParam of badObjectParams) {
      const badParamAsObject = badParam as any as object;

      try {
        encryptData({ data: badParamAsObject, secretKey: password });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

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
      encryptData({ data: undefinedParamAsObject, secretKey: password });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        issues = [...issues, error.zodErrors[0].message];
      }
    }

    try {
      encryptData({ data: fakeObject, secretKey: undefinedParamAsString });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        issues = [...issues, error.zodErrors[0].message];
      }
    }

    try {
      encryptData({
        data: undefinedParamAsObject,
        secretKey: undefinedParamAsString,
      });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const [badPwd] = error.zodErrors.map(({ message }) => message);
        issues = [...issues, badPwd];
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
  const encryptedData = encryptData({ data: fakeObject, secretKey: password });

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;

      try {
        decryptData({ encryptedData, secretKey: badParamAsString });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("secretKey must be a string");
        }
      }

      try {
        decryptData({ encryptedData: badParamAsString, secretKey: password });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toMatch("encryptedData must be a string");
        }
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;

    try {
      decryptData({
        encryptedData: undefinedParamAsString,
        secretKey: password,
      });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        issues = [...issues, error.zodErrors[0].message];
      }
    }

    try {
      decryptData({ encryptedData, secretKey: undefinedParamAsString });
    } catch (error) {
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        issues = [...issues, error.zodErrors[0].message];
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
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

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
 * @changeSecretKey function testing
 */

describe("changeSecretKey", () => {
  it("changeSecretkey encryption", () => {
    let encryptedData: string | undefined;
    for (let pwdIndex in passwords) {
      const beforePassword = passwords[Number(pwdIndex) - 1];
      const password = passwords[pwdIndex];
      if (!encryptedData) {
        encryptedData = encryptData({
          data: fakeObject,
          secretKey: passwords[pwdIndex],
        });

        expect(typeof encryptedData).toBe("string");
      } else {
        encryptedData = changeSecretKey({
          oldKey: beforePassword,
          newKey: password,
          encryptedData,
        });

        expect(decryptData({ encryptedData, secretKey: password })).toEqual(
          fakeObject
        );

        let cantDecryptWithOldPass = true;
        try {
          const decryptWillFail = decryptData({
            encryptedData,
            secretKey: beforePassword,
          });
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
        changeSecretKey({
          oldKey: badParamAsString,
          newKey: goodString,
          encryptedData: goodString,
        });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("oldKey must be a string");
        }
      }

      try {
        changeSecretKey({
          oldKey: goodString,
          newKey: badParamAsString,
          encryptedData: goodString,
        });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("newKey must be a string");
        }
      }

      try {
        changeSecretKey({
          oldKey: goodString,
          newKey: goodString,
          encryptedData: badParamAsString,
        });
      } catch (error) {
        const isEffyCryptoError = error instanceof EffyCryptoError;

        expect(isEffyCryptoError).toBe(true);

        if (isEffyCryptoError) {
          const { message } = error.zodErrors[0];

          expect(message).toBe("encryptedData must be a string");
        }
      }
    }
  });
});
