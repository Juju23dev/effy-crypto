import { ZodError } from 'zod';
import { ErrorType, EffyCryptoError } from './effy-crypto-error';
import { string } from '../utils/string';

export const fnErrorCatcher =
  <T extends (option: any) => any>(fn: T) =>
  async (option: Parameters<T>[0]) => {
    try {
      return (await fn(option)) as Awaited<ReturnType<T>>;
    } catch (error) {
      const isZodError = error instanceof ZodError;

      if (isZodError) {
        throw new EffyCryptoError({
          message: string.bad_parameters(fn.name),
          errorType: ErrorType.BadParams,
          zodErrors: error.errors,
        });
      }

      throw new EffyCryptoError({
        message: string.unknown_error,
        errorType: ErrorType.UnknownError,
        unknownError: error,
      });
    }
  };

export const fnSafeErrorCatcher =
  <T extends (option: any) => any>(fn: T) =>
  async (option: Parameters<T>[0]) => {
    try {
      const data = (await fn(option)) as Awaited<ReturnType<T>>;
      return { success: true, data };
    } catch (error) {
      const isZodError = error instanceof ZodError;

      if (isZodError) {
        return {
          success: false,
          error: new EffyCryptoError({
            message: string.bad_parameters(fn.name),
            errorType: ErrorType.BadParams,
            zodErrors: error.errors,
          }),
        };
      }

      return {
        success: false,
        error: new EffyCryptoError({
          message: string.unknown_error,
          errorType: ErrorType.UnknownError,
          unknownError: error,
        }),
      };
    }
  };

export const syncFnErrorCatcher =
  <T extends (option: any) => any>(fn: T) =>
  (option: Parameters<T>[0]) => {
    try {
      return fn(option) as ReturnType<T>;
    } catch (error) {
      const isZodError = error instanceof ZodError;

      if (isZodError) {
        throw new EffyCryptoError({
          message: string.bad_parameters(fn.name),
          errorType: ErrorType.BadParams,
          zodErrors: error.errors,
        });
      }

      throw new EffyCryptoError({
        message: string.unknown_error,
        errorType: ErrorType.UnknownError,
        unknownError: error,
      });
    }
  };

export const syncFnSafeErrorCatcher =
  <T extends (option: any) => any>(fn: T) =>
  (option: Parameters<T>[0]) => {
    try {
      const data = fn(option) as ReturnType<T>;
      return { success: true, data };
    } catch (error) {
      const isZodError = error instanceof ZodError;

      if (isZodError) {
        return {
          success: false,
          error: new EffyCryptoError({
            message: string.bad_parameters(fn.name),
            errorType: ErrorType.BadParams,
            zodErrors: error.errors,
          }),
        };
      }

      return {
        success: false,
        error: new EffyCryptoError({
          message: string.unknown_error,
          errorType: ErrorType.UnknownError,
          unknownError: error,
        }),
      };
    }
  };
