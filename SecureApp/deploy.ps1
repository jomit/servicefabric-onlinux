$endpoint = 'jomitsf.westus.cloudapp.azure.com:19000'
$thumbprint = '<CertThumbprint>'

# Connect to the cluster using a client certificate.
Connect-ServiceFabricCluster -ConnectionEndpoint $endpoint `
          -KeepAliveIntervalInSec 10 `
          -X509Credential -ServerCertThumbprint $thumbprint `
          -FindType FindByThumbprint -FindValue $thumbprint `
          -StoreLocation CurrentUser -StoreName My

$AppPath = "$PSScriptRoot\SecureApp\pkg\Debug"

Write-Host $AppPath

# Copy the application package to the cluster image store.
Copy-ServiceFabricApplicationPackage -ApplicationPackagePath $AppPath -ImageStoreConnectionString fabric:ImageStore `
-ApplicationPackagePathInImageStore SecureApp

# Register the application type.
#Register-ServiceFabricApplicationType -ApplicationPathInImageStore SecureApp

# Create the application instance.
#New-ServiceFabricApplication -ApplicationName fabric:/SecureApp `
#-ApplicationTypeName SecureAppType `
#-ApplicationTypeVersion 1.0.0
