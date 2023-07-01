# Effy-crypto

The Effy Crypto lib for hash password, encrypt data or generate jwt\
You can use it if you want 😉

## Authors

- [@Djudj_dev](https://github.com/djudj-dev)

## Install

npm:

```bash
  npm install @e2fy/effy-crypto
```

yarn:

```bash
  yarn install @e2fy/effy-crypto
```

pnpm:

```bash
  pnpm install @e2fy/effy-crypto
```

## Libs used

this lib is just functions for simplify some libs usages\
i use zod for function parameters typeguard,\
jsonwebtoken for the jwt,\
crypto-js for encryption and SHA512\
and argon2 for password hashing

### packages use in the lib

- [zod](https://www.npmjs.com/package/zod)
- [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken)
- [crypto-js](https://www.npmjs.com/package/crypto-js)
- [argon2](https://www.npmjs.com/package/argon2)

## Usage/Examples

## Passwords tools

Password tools are simplify hashing and verifying password

### `hashPassword` has 1 parameter:

a `string` ( the password you need to hash )
**example :**

```typescript
const password = "aBeautifullStrongPassword";

const hashedPassword = await hashPassword({ password });
// $argon2id$v=19$m=65536,t=3,p=4$poNY2cob9I/uVErpjW9T9w$6nF1rLoJjucA2RihlfxyMbYxA/q0NNxsD6R4Rnf8Vi4
// should be different every time argon2id use random salt
```

### `verifyPassword` has 1 parameter:

an object with 2 props :

```typescript
{
  hashedPassword: string; // a string of an hashed password
  password: string; // the password you need to verify
}
```

**example :**

```typescript
await verifyPassword({ hashedPassword, password });
//true
```

## Encryption tools

Encryption tools are for simplify data encryption decryption

### `getSecretKey` has 1 parameter:

a `string` ( a password for example )

**example :**

```typescript
const keyForEncryptData = getSecretKey(password);
// 123659a4c51aec9ca8b013b9845aeb9bffc080b67810da016077f30cc1618a3f08da1d29ff15267522a50d9d804af4264af7c8218bc840a95283b1861167c165

/*
    getSecretKey hash your string to sha512 for make a stronger key for encryption 
    with the same input you get the same output, you just need the string you used 
    for recover your key ( like a password for exemple )

    you can just use a simple string for encrypt your data but i recommend to use the getSecretKey function
    that will give you a stronger key for your data 

    and of course more complex is the string used in getSecretKey better it is 
  */
```

### `encryptData` has 1 parameter:

an object with 2 props:

```typescript
{
  data: any; // the data you need to encrypt
  secretKey: string; // the secretKey needed later for decrypt
}
```

**example :**

```typescript
const mySecretData = { data: "secret" };
const encryptedData = encryptData({
  data: mySecretData,
  secretKey: keyForEncryptData,
});
// U2FsdGVkX1/pB/wXCxDFbr8MyQBLae895+L9kB88z418ihYVbzHw+wCpa8YRqXxn
```

### `decryptData` has 1 parameter:

an object with 2 props:

```typescript
{
  encryptedData: string; // the data you encrypted
  secretKey: string; // the string key you use for encrypt
}
```

**example :**

```typescript
decryptData({ encryptedData, secretKey: keyForEncryptData });
// { data: 'secret' }
```

**And if you change your password ? 🤔**\
use `changeSecretKey`

### `changeSecretKey` has 1 parameter:

an object with 3 props:

```typescript
{
  oldKey: string; // the old key use for encryption
  newKey: string; // the new key you want to use
  encryptedData: string; // the encrypted data with old key
}
```

**example :**

```typescript
const newPassword = "aBeautifullStrongNewPassword";
const newKeyForEncryptData = getSecretKey(newPassword);

const encryptedWithNewPasswordData = changeSecretKey({
  oldKey: keyForEncryptData,
  newKey: newKeyForEncryptData,
  encryptedData,
});
// U2FsdGVkX19/zDP5YJbrEcPYnjCy+Zin8Asi5GMDCZAzR+F1H5MLaBqDE9AGf/AQ

// the old password will no longer work

try {
  decryptData({
    encryptedData: encryptedWithNewPasswordData,
    secretKey: keyForEncryptData,
  });
} catch {
  // this will trow an EffyCryptoError
}

decryptData({
  encryptedData: encryptedWithNewPasswordData,
  secretKey: newKeyForEncryptData,
});
// { data: 'secret' }
```

## JWT tools

JWT tools are for simplify JWT usage like use auth and refresh token, sign token, verify token etc..

## `createTokenTool` has 1 parameter:

an object with 2 props:

```typescript
{
  secretString: string; // secretString use for JWT
  expireIn: string; // the expiration of token
}
```

**⚠️ `expireIn` is a string of jwt expire type**\
for more informations check [jsonwebtoken doc](https://github.com/auth0/node-jsonwebtoken#token-expiration-exp-claim)

`createTokenTool` return an object with 2 props :

```typescript
{
    sign: (payload: any) => string // create a JWT
    verify: (jwt: string) => { iat: number, exp: number, data: any } // a JWT made with sign function verifier
}
```

**example :**

```typescript
const userUid = "382e3138-086f-11ee-be56-0242ac120002";

const { sign, verify } = createTokenTool("theSecretJwtString", "1h");
// create a verify and sign function with a secretKey and 1h expiration

const jwt = sign({ userUid });
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZXJVaWQiOiIzODJlMzEzOC0wODZmLTExZWUtYmU1Ni0wMjQyYWMxMjAwMDIifSwiaWF0IjoxNjg2NDk4NTczLCJleHAiOjE2ODY1MDIxNzN9.K99DB_0p1Lw9CGko9SBR4T3ZMpWEdYDXFtxLfEn015Q

verify(jwt);
/* 
    {
        data: { userUid: '382e3138-086f-11ee-be56-0242ac120002' },
        iat: 1686498573,
        exp: 1686502173
    }
*/
```

## `createAuthAndRefreshToken` has 1 parameters:

an object with 4 props :

```typescript
{
  authExpireIn: string; // the expiration of authToken
  authSecretString: string; // secretString use for auth JWT
  refreshExpireIn: string; // the expiration of refreshToken
  refreshSecretString: string; // secretString use for refresh JWT
}
```

`createAuthAndRefreshToken` return an object with 2 props :

```typescript
{
  auth: TokenTool; // a token tool for authToken
  refresh: TokenTool; // a token tool for refreshToken
}
```

**example :**

```typescript
const { auth, refresh } = createAuthAndRefreshToken({
  authExpireIn: "1h",
  authSecretString: "authSecret",
  refreshExpireIn: "24h",
  refreshSecretString: "refreshSecret",
});

// is just return auth and refresh that are two TokenTools functions
```

### `refreshingToken` has 1 parameter :

an object with 4 props:

```typescript
{
  refreshToken: string; // the Refresh token string
  authTokenTools: TokenTool; // the auth TokenTool
  refreshTokenTools: TokenTool; // the refresh TokenTool
  authTokenPayload: any: // the refreshed auth jwt payload
}
```

`createAuthAndRefreshToken` return an object with 2 props :

```typescript
{
  isJwtValid: boolean;
  token?: string; // the auth refreshed token
  error?: Error; // the error in token refreshing
}
```

**example :**

```typescript
const refreshToken = refresh.sign();

const newAuthToken = refreshingToken({
  refreshToken: refreshToken,
  authTokenTools: auth,
  refreshTokenTools: refresh,
  authTokenPayload: { userUid },
});
/*
    {
        isJwtValid: true,
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZXJVaWQiOiIzODJlMzEzOC0wODZmLTExZWUtYmU1Ni0wMjQyYWMxMjAwMDIifSwiaWF0IjoxNjg2NDk5Njg3LCJleHAiOjE2ODY1MDMyODd9.zRvcy449XQr0TSwSE42BUOiBUVHMOf98UDH7gqpEYD4'
    }
  */

if (newAuthToken.isJwtValid) {
  auth.verify(newAuthToken.token);
  /*
      {
        data: { userUid: '382e3138-086f-11ee-be56-0242ac120002' },
        iat: 1686499687,
        exp: 1686503287
      }
   */
}
```

## Errors

All functions can throw an `EffyCryptoError` \
`EffyCryptoError` have `message`, `errorType` props and can have `zodErrors` or `unknownError` also

Their is multiples `errorType`:

- `'Bad parameters'` throw when function parameters are bad
- `'Unknown error'` throw when a an unknown error append in function

## One more thing

all schema method have safe equivalent:

safe will return:

`{ success: boolean, data: /*if success*/, error: /*if error*/ }`

**⚠️ all non safe method can trow an error**

**safe methods and equivalent**:

- `hashPassword` => `safeHashPassword`
- `verifyPassword` => `safeVerifyPassword`
- `encryptData` => `safeEncryptData`
- `decryptData` => `safeDecryptData`
- `changeSecretKey` => `safeChangeSecretKey`
- `createTokenTool` => `safeCreateTokenTool`
- `createAuthAndRefreshToken` => `safeCreateAuthAndRefreshToken`
- `refreshingToken` => `safeRefreshingToken`

they all take same paramaters than the non safe equivalent

## Roadmap

- test refactorisation
- types refactorisation

and the future will say more
