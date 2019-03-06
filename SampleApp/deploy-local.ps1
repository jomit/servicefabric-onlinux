$endpoint = 'localhost:19000'

# Connect to the cluster using a client certificate.
Connect-ServiceFabricCluster -ConnectionEndpoint $endpoint

$AppPath = "$PSScriptRoot\SampleApp\pkg\Debug"

# Copy the application package to the cluster image store.
Copy-ServiceFabricApplicationPackage -ApplicationPackagePath $AppPath -ApplicationPackagePathInImageStore SampleApp

# Register the application type.
Register-ServiceFabricApplicationType -ApplicationPathInImageStore SampleApp

# Create the application instance.
New-ServiceFabricApplication -ApplicationName fabric:/SampleApp `
-ApplicationTypeName SampleAppType `
-ApplicationTypeVersion 1.0.0
