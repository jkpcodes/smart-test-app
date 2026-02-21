# 🧠 smart-test

A .NET Web API solution using a layered architecture with separate projects for API, Application, Domain, Auth, and Infrastructure.

## 📁 Solution Structure

- **🌐 API** — HTTP endpoints and hosting configuration.
  See [src/smart-test.api/Program.cs](src/smart-test.api/Program.cs)
- **⚙️ Application** — Application services and DTOs.
  See [src/smart-test.app/smart-test.app.csproj](src/smart-test.app/smart-test.app.csproj)
- **🏛️ Domain** — Core domain model.
  See [src/smart-test.domain/smart-test.domain.csproj](src/smart-test.domain/smart-test.domain.csproj)
- **🔐 Auth** — Authentication/authorization concerns.
  See [src/smart-test.auth/smart-test.auth.csproj](src/smart-test.auth/smart-test.auth.csproj)
- **🗄️ Infrastructure** — Data access and external integrations.
  See [src/smart-test.infrastructure/smart-test.infrastructure.csproj](src/smart-test.infrastructure/smart-test.infrastructure.csproj)

## ✅ Prerequisites

- 📦 .NET SDK (target framework: `net10.0`)
- 🐳 Docker installed

### 🐘 PostgreSQL (Auth Database)

```sh
docker run --name smart-test-auth-db \
  -e POSTGRES_USER=<PostgreSQL user> \
  -e POSTGRES_PASSWORD=<PostgreSQL password> \
  -e POSTGRES_DB=smart_test_auth \
  -p 5432:5432 \
  -d postgres:latest
```

### 🍃 MongoDB (Main Database)

```sh
docker run --name mongodb \
  -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=<Mongodb user> \
  -e MONGO_INITDB_ROOT_PASSWORD=<Mongodb password> \
  -d mongo:latest
```

## 🔧 Configuration

### 🔗 Connection Strings

Set `smart-test.api/appsettings.json` based on your PostgreSQL and MongoDB config:

```json
"ConnectionStrings": {
  "AuthConnectionString": "Host=localhost;Database=smart_test_auth;Username=<PostgreSQL user>;Password=<PostgreSQL password>;Port=5432",
  "MongoDbConnectionString": "mongodb://localhost:27017/smart_test",
  "MongoDbUser": "<Mongodb user>",
  "MongoDbPassword": "<Mongodb password>"
}
```

Application settings files:
- [src/smart-test.api/appsettings.json](src/smart-test.api/appsettings.json)
- [src/smart-test.api/appsettings.Development.json](src/smart-test.api/appsettings.Development.json)

### 🗃️ Run Database Migration

Initialize the Auth database in PostgreSQL:

```sh
dotnet ef database update --project src\smart-test.infrastructure.identity --startup-project src\smart-test.api
```

### 🔑 Admin User Secrets

Set `smart-test.api` user secrets to create the initial admin user on startup:

```json
{
  "AdminUser": {
    "Email": "<email>",
    "Username": "<email>",
    "Password": "<password>",
    "FirstName": "<First Name>",
    "LastName": "<Last Name>"
  }
}
```

> 💡 Use `dotnet user-secrets set` or edit the secrets file directly:
> ```sh
> dotnet user-secrets init --project src/smart-test.api
> ```

## 🏗️ Build

```sh
dotnet build
```

## 🚀 Run

```sh
dotnet run --project src/smart-test.api
```

Then open 👉 [https://localhost:7236/scalar/v1](https://localhost:7236/scalar/v1) to explore the API.