/** @type {import('jest').Config} */
module.exports = {
	testEnvironment: 'node',
	testMatch: ['<rootDir>/__tests__/**/*.test.ts'],
	transform: {
		'^.+\\.ts$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.test.json' }],
	},
	collectCoverageFrom: ['nodes/**/*.ts', 'credentials/**/*.ts'],
};
