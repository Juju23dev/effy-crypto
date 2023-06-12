import { AES, SHA512, enc } from "crypto-js";
import {
  changeSecretKeyValidator,
  decryptDataValidator,
  encryptDataValidator,
  getSecretKeyValidator,
} from "./zod.validators";

const encryptData = (data: object, secretKey: string) => {
  encryptDataValidator([data, secretKey]);

  return AES.encrypt(JSON.stringify(data), secretKey).toString();
};

const decryptData = (encryptedData: string, secretKey: string) => {
  decryptDataValidator([encryptedData, secretKey]);

  return JSON.parse(AES.decrypt(encryptedData, secretKey).toString(enc.Utf8));
};

const changeSecretKey = (
  oldKey: string,
  newKey: string,
  encryptedData: string
) => {
  changeSecretKeyValidator([oldKey, newKey, encryptedData]);

  return encryptData(decryptData(encryptedData, oldKey), newKey);
};

const getSecretKey = (keyString: string) => {
  getSecretKeyValidator(keyString);

  return SHA512(keyString).toString();
};

export { encryptData, decryptData, changeSecretKey, getSecretKey };
