# Effy Crypto

The Effy Crypto lib for hash password, encrypt data or generate jwt
You can use it if you want 😉

## Authors

- [@Djudj_dev](https://github.com/Juju23dev)

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

## Usage/Examples

```typescript
import {
  hashPassword,
  verifyPassword,
  encryptData,
  decryptData,
  getSecretKey,
  changeSecretKey,
  createTokenTool,
  createAuthAndRefreshToken,
  refreshingToken,
} from "@e2fy/effy-crypto";

(async () => {
  /*
    Password tools 
*/

  const password = "aBeautifullStrongPassword";
  const mySecretData = { data: "secret" };

  const hashedPassword = await hashPassword(password);
  // $argon2id$v=19$m=65536,t=3,p=4$poNY2cob9I/uVErpjW9T9w$6nF1rLoJjucA2RihlfxyMbYxA/q0NNxsD6R4Rnf8Vi4
  // should be different every time argon2id use random salt

  await verifyPassword(hashedPassword, password);
  //true

  /*
    Encryption tools 
*/

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

  const encryptedData = encryptData(mySecretData, keyForEncryptData);
  // U2FsdGVkX1/pB/wXCxDFbr8MyQBLae895+L9kB88z418ihYVbzHw+wCpa8YRqXxn

  decryptData(encryptedData, keyForEncryptData);
  // { data: 'secret' }

  /*
    And if you change your password ? 
*/
  const newPassword = "aBeautifullStrongNewPassword";
  const newKeyForEncryptData = getSecretKey(newPassword);

  const encryptedWithNewPasswordData = changeSecretKey(
    keyForEncryptData,
    newKeyForEncryptData,
    encryptedData
  );
  // U2FsdGVkX19/zDP5YJbrEcPYnjCy+Zin8Asi5GMDCZAzR+F1H5MLaBqDE9AGf/AQ

  /*
    the old password will no longer work 
*/

  try {
    decryptData(encryptedWithNewPasswordData, keyForEncryptData);
  } catch {
    // this will trow an error
  }

  decryptData(encryptedWithNewPasswordData, newKeyForEncryptData);
  // { data: 'secret' }

  /*
    jwt tools 
*/

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

  const { auth, refresh } = createAuthAndRefreshToken({
    authExpireIn: "1h",
    authSecretString: "authSecret",
    refreshExpireIn: "24h",
    refreshSecretString: "refreshSecret",
  });

  // is just return auth and refresh that are two TokenTools functions

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

  // and that's all
})();
```

### ⚠️ warning !!

all function need to be try catch they can throw Zod Error if parameter is invalid or other Error depending on function

## Roadmap

- create personalized errors
- test refactorisation
- types refactorisation

and the future will say more
