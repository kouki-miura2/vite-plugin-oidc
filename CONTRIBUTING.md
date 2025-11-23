# Contributing to vite-plugin-oidc

Thank you for your interest in contributing to vite-plugin-oidc! We welcome contributions from the community.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [TypeScript Coding Style](#typescript-coding-style)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your feature or bugfix
4. Make your changes
5. Test your changes
6. Submit a pull request

## Development Setup

### Prerequisites

- Node.js (version 18 or higher recommended)
- npm or pnpm

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vite-plugin-oidc.git
cd vite-plugin-oidc

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test
```

### Available Scripts

- `npm run build` - Build the project (TypeScript compilation + copy assets)
- `npm run dev` - Watch mode for development (TypeScript compilation)
- `npm test` - Run tests once
- `npm run test:watch` - Run tests in watch mode
- `npm run test:coverage` - Run tests with coverage report

## TypeScript Coding Style

This project follows specific TypeScript coding conventions. Please adhere to these guidelines when contributing:

- **No semicolons**: Do not use semicolons at the end of statements
- **Trailing commas**: Use trailing commas in multi-line objects, arrays, and function parameters
- **Single quotes**: Use single quotes for strings (except when avoiding escaping)
- **2-space indentation**: Use 2 spaces for indentation
- **Type annotations**: Always use explicit type annotations for function parameters and return types
- **Interface vs Type**: Prefer `interface` for object types, use `type` for unions and complex types
- **Arrow functions**: Use arrow functions for class methods where appropriate
- **Async/await**: Prefer async/await over Promise chains
- **Explicit return types**: Always specify return types for functions and methods
- **Import extensions**: Use `.js` extension in import statements (for ES modules compatibility)
- **Avoid `any`**: Use specific types instead of `any` whenever possible
- **Null safety**: Handle null/undefined cases explicitly
- **JSDoc comments**: Add JSDoc comments for public APIs and complex functions
- **Destructuring**: Use object destructuring where it improves readability
- **Const over let**: Use `const` by default, `let` only when reassignment is needed
- **Template literals**: Use template literals for string interpolation

### Example

```typescript
/**
 * Validates the token request parameters
 * @param params The token request parameters
 * @returns Validation result with error details if invalid
 */
validateTokenRequest(params: TokenParams): ValidationResult {
  return ValidationUtil.validateTokenRequest(params, this.clients)
}

async handleToken(req: Request, res: Response): Promise<void> {
  const requestId = this.generateRequestId()

  try {
    // Parse token request parameters from body
    const params = await this.parseTokenParams(req)

    // Validate the token request
    const validation = this.validateTokenRequest(params)

    if (!validation.isValid) {
      this.sendErrorResponse(res, validation.error!)
      return
    }

    // Exchange authorization code for tokens
    const tokenResponse = this.exchangeCodeForTokens(
      params.code,
      params.code_verifier,
    )

    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify(tokenResponse))
  } catch (error) {
    const oidcError = ValidationUtil.createErrorResponse(
      'server_error',
      'Internal server error',
    )
    this.sendErrorResponse(res, oidcError)
  }
}
```

## Project Structure

```
vite-plugin-oidc/
├── src/
│   ├── assets/
│   │   └── templates/      # HTML templates for login UI
│   ├── handlers/           # OIDC endpoint handlers
│   │   ├── AuthorizationHandler.ts
│   │   ├── TokenHandler.ts
│   │   ├── UserInfoHandler.ts
│   │   ├── LoginUIHandler.ts
│   │   └── ...
│   ├── services/           # Core business logic
│   │   └── TokenService.ts
│   ├── storage/            # In-memory data storage
│   │   └── InMemoryStore.ts
│   ├── utils/              # JWT, PKCE, and validation utilities
│   │   ├── JWTUtil.ts
│   │   ├── PKCEUtil.ts
│   │   ├── ValidationUtil.ts
│   │   └── Logger.ts
│   ├── types/              # TypeScript type definitions
│   │   ├── config.ts
│   │   ├── handlers.ts
│   │   ├── oidc.ts
│   │   └── storage.ts
│   ├── middleware/         # Express-style middleware
│   │   └── index.ts
│   └── index.ts            # Main entry point
├── examples/               # Example applications
│   └── basic/              # Basic OIDC client example
├── dist/                   # Build output
└── test/                   # Test files
```

### Key Components

- **Handlers**: Handle specific OIDC endpoints (authorization, token, userinfo, etc.)
- **Services**: Business logic for token generation and validation
- **Storage**: In-memory storage for authorization codes, tokens, and sessions
- **Utils**: Helper functions for JWT, PKCE, validation, and logging
- **Types**: TypeScript type definitions for configuration and internal types

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

### Writing Tests

- Place test files in the `test/` directory
- Use descriptive test names that explain what is being tested
- Follow the Arrange-Act-Assert pattern
- Test both success and error cases
- Mock external dependencies where appropriate

### Example Application

The `examples/basic/` directory contains a working example of an OIDC client that can be used to test the plugin:

```bash
cd examples/basic
npm install
npm run dev
```

## Submitting Changes

### Pull Request Process

1. **Create a feature branch** from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding style guidelines

3. **Test your changes**:

   ```bash
   npm test
   npm run build
   ```

4. **Format your code** with Prettier:

   ```bash
   pnpm exec prettier . --write
   ```

5. **Commit your changes** with a clear commit message:

   ```bash
   git commit -m "Add feature: description of your changes"
   ```

6. **Push to your fork**:

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Submit a pull request** to the `main` branch of the original repository

### Commit Message Guidelines

- Use clear and descriptive commit messages
- Start with a verb in present tense (e.g., "Add", "Fix", "Update", "Remove")
- Keep the first line under 72 characters
- Add detailed description in the body if necessary

Examples:

```
Add support for refresh tokens
Fix PKCE validation for edge cases
Update README with new configuration options
Remove deprecated token endpoint
```

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Your environment (Node.js version, OS, etc.)
- Any relevant error messages or logs

### Feature Requests

When requesting features, please include:

- A clear and descriptive title
- The problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered
- Additional context or examples

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Assume good intentions

## Questions?

If you have questions about contributing, feel free to:

- Open an issue on GitHub
- Check existing issues and pull requests
- Review the README.md for project documentation

Thank you for contributing to vite-plugin-oidc!
