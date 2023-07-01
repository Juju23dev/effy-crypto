import { hash, verify } from 'argon2';
import { fnErrorCatcher, fnSafeErrorCatcher } from '../errors/wrap-fn-error';
import { hashPasswordValidator, verifyPasswordValidator } from './zod.validators';

const hashPasswordFn = async (password: string) => {
  hashPasswordValidator(password);
  return hash(password);
};

const verifyPasswordFn = async (params: { hashedPassword: string; password: string }) => {
  const { hashedPassword, password } = verifyPasswordValidator(params);

  return verify(hashedPassword, password);
};

export const { hashPassword, safeHashPassword, verifyPassword, safeVerifyPassword } = {
  hashPassword: fnErrorCatcher(hashPasswordFn),
  safeHashPassword: fnSafeErrorCatcher(hashPasswordFn),
  verifyPassword: fnErrorCatcher(verifyPasswordFn),
  safeVerifyPassword: fnSafeErrorCatcher(verifyPasswordFn),
};
