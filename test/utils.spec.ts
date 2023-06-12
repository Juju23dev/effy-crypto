import { faker } from "@faker-js/faker";

export const badStringParams = [
  12,
  { bad: "params" },
  ["bad", "params"],
  true,
  false,
  null,
  [],
];

export const badObjectParams = [12, "test", false, null];

const passwords: string[] = [];
for (let i = 0; i <= 10; i++) {
  passwords.push(faker.internet.password({ length: 10 }));
}

const randomStrings: string[] = [];
for (let i = 0; i <= 10; i++) {
  randomStrings.push(faker.internet.password({ length: 20 }));
}

export const fakeObject = { data: "test" };

export { passwords, randomStrings };
