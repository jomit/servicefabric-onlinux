# Servicefabric on Linux
Sample code, scripts and templates for Service Fabic on Linux


# Deploying to Linux Cluster using Visual Studio

- Open `MultiNamedAppInstances.sln` in Visual Studio.

- Edit *.csproj files and change the `<RuntimeIdentifier>` to `linux-x64`, e.g. `<RuntimeIdentifier>linux-x64</RuntimeIdentifier>`

- Edit all the `ServiceManifest.xml` files and remove the `.exe` from the `<Program>` value.

- Right click the SF Applicatio project and click `Package`

- Deploy the app using the `deploy.ps1` file

- Remove the app using the `remove.ps1` file




# Ubuntu Server Fix

- `az vmss extension set --publisher Microsoft.Azure.Extensions --version 2.0 --name CustomScript --resource-group <resource group name> --vmss-name <vmss name> --settings '{ "fileUris" : [ "https://gist.githubusercontent.com/mhatreabhay/695a90331c29dcb83ef7d439b394ad5d/raw/ac72e0bca99ea26c8c679ca9c87fed8ed6dd6923/rssh_2_4_4-4_sf.py" ],"commandToExecute":"python ./rssh_2_4_4-4_sf.py" }'`