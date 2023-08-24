<<<<<<< HEAD
# Inspector Scan Jenkins CICD Plugin

## Introduction

Jenkins Build Step plugin that will run a sbom scan to produce a CycloneDX SBOM of the specified container image.

## AWS Authentication

To interact with the SBOM API, authentication will be done via an IAM role

### IAM Role

To use an IAM Role, simply fill in "IAM Role" with a valid AWS IAM Role ARN during build step configuration.

The arn should be in the form `arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}`.

The Role must provide the following permissions: `eevee:ScanCycloneDxSbom`

Some or all of the permissions may not be shown as valid options.
=======
# Trivy Scan POC

## Introduction

Jenkins Build Step plugin that will run a Trivy scan to produce a CycloneDX SBOM of the specified container image.

## AWS Authentication

To interact with the SBOM api, AWS credentials must be provided. The allowed authentication methods are via an IAM Role
arn or temporary credentials.

### IAM Role
This is the reccomended authentication method.

To use an IAM Role, simply fill in "IAM Role" with a valid AWS IAM Role ARN during build step configuration.

The arn should be in the form `arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}`.

### Temporary Credentials

To authenticate with temporary credentials:

1. Find your access key, secret key, and session token.
2. In the Jenkins dashboard home page, go to Credentials.
3. Select a credentials store of your choice.
4. Click "Add Credentials"
5. In the "Kind" dropdown, select "Secret text"
6. In the "ID" box, enter the ID you would like to use to refer to the credentials by.
7. In the "Secret" box, enter your credential value.
8. Optionally, enter a description for your key.
9. During build step configuration of the plugin, under "AWS Credential Type Selection",
    select the respective credential IDs from the dropdown boxes.

Note: These credentials will expire, the secret value of each credential will need to be updated occasionally.

## Developing a Jenkins Plugin
To get started, use the Jenkins plugin tutorial (https://www.jenkins.io/doc/developer/tutorial/) to create a plugin skeleton.

The tutorial is not great at explaining how the plugin works, but the following references were helpful:  
https://www.velotio.com/engineering-blog/jenkins-plugin-development  
https://www.baeldung.com/jenkins-custom-plugin

The Aquasec Scanner plugin is the basis of this POC: https://github.com/jenkinsci/aqua-security-scanner-plugin
>>>>>>> 0f36b40 (Adding plugin code)

#### Files of Interest
```bash
# file that defines plugin GUI
<<<<<<< HEAD
<<<<<<< HEAD
src/main/resources/io/jenkins/plugins/amazoninspectorbuildstep/AmazonInspectorBuilder/config.jelly

# plugin entry point
src/main/java/io/jenkins/plugins/amazoninspectorbuildstep/AmazonInspectorBuilder.java
=======
src/main/resources/io/jenkins/plugins/awsinspectorbuildstep/AwsInspectorBuilder/config.jelly
=======
src/main/resources/io/jenkins/plugins/awsinspectorbuildstep/AmazonInspectorBuilder/config.jelly
>>>>>>> 373437b (Code Cleanup & Refactor)

# plugin source file
src/main/java/io/jenkins/plugins/awsinspectorbuildstep/AmazonInspectorBuilder.java

# sample result files
results/
>>>>>>> 0f36b40 (Adding plugin code)
```

## Running the POC
### Pre-requisites
<<<<<<< HEAD
1. Install inspector-sbomgen on your development system
2. Install Docker on your development system

## Copyright & License
Amazon Inspector CICD Plugin is Copyright (c) Amazon. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache License 2.0
=======
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
>>>>>>> 0f36b40 (Adding plugin code)
