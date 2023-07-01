import { ZodError } from 'zod';

export const enum ErrorType {
  BadParams = 'Bad parameter',
  UnknownError = 'Unknown error',
}

export class EffyCryptoError extends Error {
  public errorType;

  public zodErrors;

  public unknownError;

  constructor({
    message,
    errorType,
    zodErrors,
    unknownError,
  }: {
    message: string;
    errorType: ErrorType;
    zodErrors?: ZodError['errors'];
    unknownError?: unknown;
  }) {
    super();
    this.message = message;
    this.errorType = errorType;
    this.zodErrors = zodErrors;
    this.unknownError = unknownError;
  }
}
