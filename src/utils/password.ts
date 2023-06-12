import { hash, verify } from "argon2";
import {
  hashPasswordValidator,
  verifyPasswordValidator,
} from "./zod.validators";

const hashPassword = (password: string) => {
  hashPasswordValidator(password);

  return hash(password);
};

const verifyPassword = (hashedPassword: string, password: string) => {
  verifyPasswordValidator([hashedPassword, password]);

  return verify(hashedPassword, password);
};

export { hashPassword, verifyPassword };
