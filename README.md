The Jenkins plugin leverages the Amazon Inspector SBOM Generator binary and Amazon Inspector Scan API to produce detailed reports at the end of your build, so you can investigate and remediate risk before deployment.

Amazon Inspector is a vulnerability management service that scans container images for operating system and programming language package vulnerabilities based on CVEs.

Using the Amazon Inspector Jenkins plugin, you can add Amazon Inspector vulnerability scans to your Jenkins pipeline.

#### 1. Set up an AWS account
* Configure an AWS account with an IAM role that allows access to the Amazon Inspector Scan API.

#### 2. Install the Inspector Jenkins Plugin
1. From your Jenkins dashboard, go to **Manage Jenkins > Manage Plugins** and select the **Available** tab.
2. Choose Available.
3. From the Available tab, search for Amazon Inspector Scans, and then install the plugin.

#### 3. Install the Inspector SBOM Generator
* Install and configure the Amazon Inspector SBOM Generator. For instructions, see [Installing Amazon Inspector SBOM Generator (Sbomgen)](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html)

#### 4. Add your Docker credentials to Jenkins
The following procedure describes how to add docker credentials to Jenkins from the Jenkins dashboard.

1. From the Jenkins dashboard, choose Manage Jenkins, Credentials, and then System.
2. Choose Global credentials and then Add credentials.
3. For Kind, select Username with password.
4. For Scope, select Global (Jenkins, nodes, items, all child items, etc).
5. Enter your details, and then choose OK.

#### 5. Add an Amazon Inspector Scan build step to your project
1. On the configuration page, scroll down to **Build Steps**, select **Add build step** and select **Amazon Inspector Scan**.
2. Configure the Amazon Inspector Scan build step by filling in following details:
    * Select one of the following Inspector-SBOMGen installation methods:
        * Automatic: Download the most recent version of inspector-sbomgen, based on operating system and CPU architecture.
        * Manual: Provide an absolute path to a downloaded version of inspector-sbomgen.
          * Download: https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html#install-sbomgen
    * For **Path to inspector-sbomgen** add the installation path to your Amazon Inspector SBOM Generator generator.
    * For **Image Id** input the path to your image. Your image can be local, remote, or archived. Image names should follow the Docker naming convention. If analyzing an exported image, provide the path to the expected tar file. See the following example Image Id paths:
        * For local or remote containers: `NAME[:TAG|@DIGEST]`
        * For a tar file: `/path/to/image.tar`
    * For private registry and container images, please refer to https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html
    * Select an **AWS Region** to send the scan request through.
    * (Optional) For IAM role, provide a role ARN (arn:aws:iam::AccountNumber:role/RoleName).
    * (Optional) For AWS credentials, select Id to authenticate based on an IAM user.
    * (Optional) For AWS profile name, provide the name of a profile to authenticate using a profile name.
    * (Optional) Specify the **Vulnerability thresholds** per severity. If the number you specify is exceeded during a scan the image build will fail. If the values are all 0 the build will succeed regardless of the number of vulnerabilities found.
3. Select **Save**.

#### 6. View your Amazon Inspector vulnerability report
1. Complete a new build of your project.
2. When the build completes select an output format from the results.
3. (Optional) Enable CSS support in Jenkins script console to allow HTML report links to open: https://www.jenkins.io/doc/book/security/user-content/

### Troubleshooting

Issue #1: If you receive the following error:

InstanceProfileCredentialsProvider(): Failed to load credentials from IMDS.

Resolution : Set up aws_access_key_id and aws_secret_access_key in ~/.aws/credential

### Known Limitations and Issues

* Support for Windows OS and macOS is not provided at this time.
* Sbomgen was load tested against container images spanning 5 GB in size, 60 layers, and 2,000 installed packages. Sbomgen should be able to inventory images of this size within 5 minutes; however, this may vary depending on the configuration of your image and available hardware resources.
* Sbomgen prioritizes accuracy and low false positive rates, which often comes at the expense of speed.
* Sbomgen only generates SBOMs - it does not perform vulnerability identification at this time.
* Sbomgen only generates SBOMs in CycloneDX + JSON format at this time.
