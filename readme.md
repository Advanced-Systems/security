<p align="center">
  <a title="Project Logo">
    <img height="150" style="margin-top:15px" src="https://raw.githubusercontent.com/Advanced-Systems/vector-assets/master/advanced-systems-logo-annotated.svg">
  </a>
</p>

<h1 align="center">Advanced Systems Security</h1>

The `AdvancedSystems.Security` library provides classes and services for symmetric and
asymmetric standard cryptographic algorithms based on the .NET cryptography system.

## Development Environment

This project uses [stryker](https://stryker-mutator.io/) for mutation testing, which is
setup to be installed with

```powershell
dotnet tool restore
```

Run stryker locally:

```powershell
dotnet stryker
```