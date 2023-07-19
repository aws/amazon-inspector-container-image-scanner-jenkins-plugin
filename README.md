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

#### Files of Interest
```bash
# file that defines plugin GUI
src/main/resources/io/jenkins/plugins/amazoninspectorbuildstep/AmazonInspectorBuilder/config.jelly

# plugin entry point
src/main/java/io/jenkins/plugins/amazoninspectorbuildstep/AmazonInspectorBuilder.java
```

## Running the POC
### Pre-requisites
1. Install inspector-sbomgen on your development system
2. Install Docker on your development system

## Copyright & License
Amazon Inspector CICD Plugin is Copyright (c) Amazon. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache License 2.0