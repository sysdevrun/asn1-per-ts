module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  moduleNameMapper: {
    '^asn1-per-ts$': '<rootDir>/../src',
  },
  modulePaths: ['<rootDir>/node_modules', '<rootDir>/../node_modules'],
  transform: {
    '^.+\\.[jt]sx?$': ['ts-jest', { diagnostics: false }],
  },
  transformIgnorePatterns: [
    'node_modules/(?!@noble/)',
  ],
};
