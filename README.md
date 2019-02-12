# Servicefabric on Linux
Sample code, scripts and templates for Service Fabic on Linux


# Deploying to Linux Cluster using Visual Studio

- Open `MultiNamedAppInstances.sln` in Visual Studio.

- Edit *.csproj files and change the `<RuntimeIdentifier>` to `linux-x64`, e.g. `<RuntimeIdentifier>linux-x64</RuntimeIdentifier>`

- Edit all the `ServiceManifest.xml` files and remove the `.exe` from the `<Program>` value.

- Right click the SF Applicatio project and click `Package`

- Deploy the app using the `deploy.ps1` file

- Remove the app using the `removeapp.ps1` file
