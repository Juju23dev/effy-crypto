import {
  encryptData,
  decryptData,
  getSecretKey,
  changeSecretKey,
} from "./utils/encrypt";
import { hashPassword, verifyPassword } from "./utils/password";
import {
  createTokenTool,
  createAuthAndRefreshToken,
  refreshingToken,
} from "./utils/jwt";

export default {
  hashPassword,
  verifyPassword,
  getSecretKey,
  encryptData,
  decryptData,
  changeSecretKey,
  createTokenTool,
  createAuthAndRefreshToken,
  refreshingToken,
};

export {
  hashPassword,
  verifyPassword,
  getSecretKey,
  encryptData,
  decryptData,
  changeSecretKey,
  createTokenTool,
  createAuthAndRefreshToken,
  refreshingToken,
};
