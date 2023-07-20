# Trivy Scan POC

## Introduction

Jenkins Build Step plugin that will run a Trivy scan to produce a CycloneDX SBOM of the specified container image.

## Developing a Jenkins Plugin
To get started, use the Jenkins plugin tutorial (https://www.jenkins.io/doc/developer/tutorial/) to create a plugin skeleton.

The tutorial is not great at explaining how the plugin works, but the following references were helpful:  
https://www.velotio.com/engineering-blog/jenkins-plugin-development  
https://www.baeldung.com/jenkins-custom-plugin

The Aquasec Scanner plugin is the basis of this POC: https://github.com/jenkinsci/aqua-security-scanner-plugin

#### Files of Interest
```bash
# file that defines plugin GUI
src/main/resources/io/jenkins/plugins/awsinspectorbuildstep/AwsInspectorBuilder/config.jelly

# plugin source file
src/main/java/io/jenkins/plugins/awsinspectorbuildstep/AwsInspectorBuilder.java

# sample result files
results/
```

## Running the POC
### Pre-requisites
1. Install Trivy on your development system (https://github.com/aquasecurity/trivy#quick-start)
2. Install Docker on your development system (to test the local image option)

### Configuring & Running the Plugin
The plugin currently supports three types of container images: local, remote, and Docker archive.
```bash
# to start a Jenkins instance with the plugin
# run this command in the project directory:
mvn hpi:run

# navigate to http://localhost:8080/jenkins/
1. Click "+ New Item" 
2. Enter a new
3. Select "Freestyle Project"
4. Click the "Ok" button
5. Select "AWS Inspector Scan" from the "Add Build Step" drop down 
6. Choose one of container image options:
    a. Local 
        Enter the container <image:version> (e.g. redis:latest)
    b. Remote 
        Enter the container <image:version> (e.g. redis:latest)
        Enter the registry URL (e.g. public.ecr.aws/ubuntu/) # this seems a little incomplete
    c. Docker Archive
        Enter the path to the container image archive
7. Click the "Save" button
8. Click the "Build Now" button
9. Check "<project dir>/work/workspace/<build job name>" for the SBOM file
```