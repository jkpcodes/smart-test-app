# 🧪 SmartTest Frontend

Angular frontend application for the SmartTest platform.

## Prerequisites

- [Node.js](https://nodejs.org/) (v20 or later)
- [Angular CLI](https://angular.dev/tools/cli) (v19 or later)

```sh
npm install -g @angular/cli
```

## Getting Started

### Install Dependencies

```sh
cd src/smart-test-fe
npm install
```

### Development Server

```sh
ng serve
```

Navigate to 👉 [http://localhost:4200](http://localhost:4200). The app will automatically reload when you change source files.

### Build

```sh
ng build
```

Build artifacts are stored in the `dist/` directory.

### Run Unit Tests

```sh
ng test
```

### Run End-to-End Tests

```sh
ng e2e
```

> **Note:** You need to install an e2e testing framework first (e.g., [Cypress](https://www.cypress.io/) or [Playwright](https://playwright.dev/)).

## Project Structure

```
src/smart-test-fe/
├── src/
│   ├── app/
│   │   ├── app.component.ts       # Root component
│   │   ├── app.html                # Root template
│   │   ├── app.config.ts           # App configuration
│   │   └── app.routes.ts           # Route definitions
│   ├── environments/               # Environment configs
│   ├── index.html                  # Entry HTML
│   ├── main.ts                     # Bootstrap entry point
│   └── styles.css                  # Global styles
├── angular.json                    # Angular workspace config
├── package.json                    # Dependencies
├── tsconfig.json                   # TypeScript config
└── README.md
```

## API Integration

This frontend connects to the SmartTest .NET API. Ensure the backend is running before starting the frontend.

**API Base URL (Development):** `https://localhost:7236`

See the [root README](../../README.md) for backend setup instructions.

## Resources

- [Angular Documentation](https://angular.dev)
- [Angular CLI Reference](https://angular.dev/tools/cli)
- [Angular Tutorials](https://angular.dev/tutorials)