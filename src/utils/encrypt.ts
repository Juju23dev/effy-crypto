import { AES, SHA512, enc } from 'crypto-js';
import { syncFnErrorCatcher, syncFnSafeErrorCatcher } from '../errors/wrap-fn-error';
import {
  changeSecretKeyValidator,
  decryptDataValidator,
  encryptDataValidator,
  getSecretKeyValidator,
} from './zod.validators';

const encryptDataFn = (params: { data: any; secretKey: string }) => {
  const { data, secretKey } = encryptDataValidator(params);

  return AES.encrypt(JSON.stringify(data), secretKey).toString();
};

const decryptDataFn = (params: { encryptedData: string; secretKey: string }) => {
  const { encryptedData, secretKey } = decryptDataValidator(params);

  return JSON.parse(AES.decrypt(encryptedData, secretKey).toString(enc.Utf8));
};

const changeSecretKeyFn = (params: { oldKey: string; newKey: string; encryptedData: string }) => {
  const { oldKey, newKey, encryptedData } = changeSecretKeyValidator(params);

  return encryptDataFn({
    data: decryptDataFn({ encryptedData, secretKey: oldKey }),
    secretKey: newKey,
  });
};

const getSecretKeyFn = (keyString: string) => {
  getSecretKeyValidator(keyString);

  return SHA512(keyString).toString();
};

export const {
  encryptData,
  safeEncryptData,
  decryptData,
  safeDecryptData,
  changeSecretKey,
  safeChangeSecretKey,
  getSecretKey,
  safeGetSecretKey,
} = {
  encryptData: syncFnErrorCatcher(encryptDataFn),
  safeEncryptData: syncFnSafeErrorCatcher(encryptDataFn),
  decryptData: syncFnErrorCatcher(decryptDataFn),
  safeDecryptData: syncFnSafeErrorCatcher(decryptDataFn),
  changeSecretKey: syncFnErrorCatcher(changeSecretKeyFn),
  safeChangeSecretKey: syncFnSafeErrorCatcher(changeSecretKeyFn),
  getSecretKey: syncFnErrorCatcher(getSecretKeyFn),
  safeGetSecretKey: syncFnSafeErrorCatcher(getSecretKeyFn),
};
