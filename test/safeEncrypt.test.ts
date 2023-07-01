import { describe, expect, it } from "vitest";
import {
  decryptData,
  encryptData,
  safeChangeSecretKey,
  safeDecryptData,
  safeEncryptData,
  safeGetSecretKey,
} from "../src/utils/encrypt";
import { SHA512 } from "crypto-js";
import {
  badStringParams,
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
      const encryptedData = safeEncryptData({
        data: fakeObject,
        secretKey: password,
      });

      expect(encryptedData.success).toBe(true);

      if (!encryptedData.success || !encryptedData.data) {
        throw new Error("should never happen");
      }

      const dataDecrypted = safeDecryptData({
        encryptedData: encryptedData.data,
        secretKey: password,
      });

      expect(dataDecrypted.success).toBe(true);
      expect(dataDecrypted.data).toEqual(fakeObject);
    }
  });

  it("with bad password", () => {
    const password = "MyGoodPassword";
    const encryptedData = safeEncryptData({
      data: fakeObject,
      secretKey: password,
    });

    expect(encryptedData.success).toBe(true);

    if (!encryptedData.success || !encryptedData.data) {
      throw new Error("should never happen");
    }

    let errCount = 0;
    for (let badPassword of passwords) {
      const data = safeDecryptData({
        encryptedData: encryptedData.data,
        secretKey: badPassword,
      });
      !data.success && errCount++;

      expect(data.error instanceof EffyCryptoError).toBe(true);
      expect(data.error?.unknownError).toBeDefined();
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
      const data = safeEncryptData({
        data: fakeObject,
        secretKey: badParamAsString,
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

        expect(message).toBe("secretKey must be a string");
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;
    const undefinedParamAsObject = undefined as any as object;

    const data = safeEncryptData({
      data: fakeObject,
      secretKey: undefinedParamAsString,
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

    const data2 = safeEncryptData({
      data: undefinedParamAsObject,
      secretKey: undefinedParamAsString,
    });

    expect(data2.success).toBe(false);

    if (data2.success || !data2.error) {
      throw new Error("should never happen");
    }

    const { error: error2 } = data2;
    const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

    expect(isEffyCryptoError2).toBe(true);

    if (isEffyCryptoError2) {
      const [badPwd] = error2.zodErrors.map(({ message }) => message);
      issues = [...issues, badPwd];
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
      const data = safeDecryptData({
        encryptedData,
        secretKey: badParamAsString,
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

        expect(message).toBe("secretKey must be a string");
      }

      const data2 = safeDecryptData({
        encryptedData: badParamAsString,
        secretKey: password,
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

        expect(message).toMatch("encryptedData must be a string");
      }
    }
  });

  it("with undefined params", () => {
    let issues: string[] = [];
    const undefinedParamAsString = undefined as any as string;

    const data = safeDecryptData({
      encryptedData: undefinedParamAsString,
      secretKey: password,
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

    const data2 = safeDecryptData({
      encryptedData,
      secretKey: undefinedParamAsString,
    });

    expect(data2.success).toBe(false);

    if (data2.success || !data2.error) {
      throw new Error("should never happen");
    }

    const { error: error2 } = data2;
    const isEffyCryptoError2 = error2 instanceof EffyCryptoError;

    expect(isEffyCryptoError).toBe(true);

    if (isEffyCryptoError2) {
      issues = [...issues, error2.zodErrors[0].message];
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
      const key = safeGetSecretKey(string);

      expect(key.success).toBe(true);
      expect(SHA512(string).toString()).toEqual(key.data);
    }
  });

  it("with bad params", () => {
    for (let badParam of badStringParams) {
      const badParamAsString = badParam as any as string;
      const data = safeGetSecretKey(badParamAsString);

      expect(data.success).toBe(false);

      if (data.success || !data.error) {
        throw new Error("should never happen");
      }

      const { error } = data;
      const isEffyCryptoError = error instanceof EffyCryptoError;

      expect(isEffyCryptoError).toBe(true);

      if (isEffyCryptoError) {
        const { message } = error.zodErrors[0];

        expect(message).toBe("keyString must be a string");
      }
    }
  });

  it("with undefined params", () => {
    const undefinedParamAsString = undefined as any as string;
    const data = safeGetSecretKey(undefinedParamAsString);

    expect(data.success).toBe(false);

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
 * @changeSecretKey function testing
 */

describe("changeSecretKey", () => {
  it("changeSecretkey encryption", () => {
    let encryptedData:
      | { success: boolean; data?: string; error?: unknown }
      | undefined;
    for (let pwdIndex in passwords) {
      const beforePassword = passwords[Number(pwdIndex) - 1];
      const password = passwords[pwdIndex];

      if (!encryptedData) {
        encryptedData = safeEncryptData({
          data: fakeObject,
          secretKey: passwords[pwdIndex],
        });

        expect(encryptedData.success).toBe(true);

        if (!encryptedData.success || !encryptedData.data) {
          throw new Error("should never happen");
        }

        expect(typeof encryptedData.data).toBe("string");
      } else {
        if (!encryptedData.success || !encryptedData.data) {
          throw new Error("should never happen");
        }

        encryptedData = safeChangeSecretKey({
          oldKey: beforePassword,
          newKey: password,
          encryptedData: encryptedData.data,
        });

        expect(encryptedData.success).toBe(true);

        if (!encryptedData.success || !encryptedData.data) {
          throw new Error("should never happen");
        }

        expect(
          decryptData({
            encryptedData: encryptedData.data,
            secretKey: password,
          })
        ).toEqual(fakeObject);

        let cantDecryptWithOldPass = true;
        try {
          const decryptWillFail = decryptData({
            encryptedData: encryptedData.data,
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
      const data = safeChangeSecretKey({
        oldKey: badParamAsString,
        newKey: goodString,
        encryptedData: goodString,
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

        expect(message).toBe("oldKey must be a string");
      }

      const data2 = safeChangeSecretKey({
        oldKey: goodString,
        newKey: badParamAsString,
        encryptedData: goodString,
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

        expect(message).toBe("newKey must be a string");
      }

      const data3 = safeChangeSecretKey({
        oldKey: goodString,
        newKey: goodString,
        encryptedData: badParamAsString,
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

        expect(message).toBe("encryptedData must be a string");
      }
    }
  });
});
