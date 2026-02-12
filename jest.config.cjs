/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  projects: [
    {
      displayName: 'lib',
      preset: 'ts-jest',
      testEnvironment: 'node',
      roots: ['<rootDir>/tests'],
      testMatch: ['**/*.test.ts'],
      collectCoverageFrom: ['src/**/*.ts'],
      moduleNameMapper: {
        '^asn1-per-ts$': '<rootDir>/src',
      },
      transform: {
        '^.+\\.tsx?$': ['ts-jest', {
          tsconfig: {
            target: 'ES2020',
            module: 'commonjs',
            lib: ['ES2020'],
            strict: true,
            esModuleInterop: true,
            resolveJsonModule: true,
            skipLibCheck: true,
            forceConsistentCasingInFileNames: true,
            baseUrl: '.',
            paths: {
              'asn1-per-ts': ['./src'],
            },
          },
        }],
      },
    },
    '<rootDir>/intercode6-ts',
  ],
};
