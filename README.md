This plugin gives you the ability to add Amazon Inspector vulnerability scans to your pipeline. These scans leverage the Inspector SBOM generator binary and Amazon Inspector Scan API to produce detailed reports at the end of your build so you can investigate and remediate risk before deployment. The scans can also be configured to pass or fail pipeline executions based on the number and severity of vulnerabilities detected.

Amazon Inspector is a vulnerability management service offered by AWS that scans container images for both operating system and programming language package vulnerabilities based on CVEs. For more information on Amazon Inspector's CI/CD integration see [Integrating Amazon Inspector scans into your CI/CD pipeline](https://docs.aws.amazon.com/inspector/latest/user/scanning-cicd.html).

For a list of packages and container image formats the Inspector plugin supports see, [Supported packages and image formats](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html#sbomgen-supported).

Follow the steps in each section of this document to use the Inspector Jenkins plugin:

#### 1. Set up an AWS account
* Configure an AWS account with an IAM role that allows access to the Inspector SBOM scanning API. For instructions, see [Setting up an AWS account to use the Amazon Inspector CI/CD integration](https://docs.aws.amazon.com/inspector/latest/user/configure-cicd-account.html)

#### 2. Install the Inspector Jenkins Plugin
1. From your Jenkins dashboard, go to **Manage Jenkins > Manage Plugins** and select the **Available** tab.
2. Search for **Amazon Inspector Scans**.
3. Install the plugin.

#### 3. Install the Inspector SBOM Generator
* Install and configure the Amazon Inspector SBOM Generator. For instructions, see [Installing Amazon Inspector SBOM Generator (Sbomgen)](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html)

#### 4. Add your Docker credentials to Jenkins
1. Go to **Dashboard > Manage Jenkins > Credentials > System > Global credentials > Add credentials**.
2. Fill in details and select **Create**.

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
    * For **IAM Role** enter the ARN for the role you configured in step 1.
    * For **Docker credentials** select your Docker username.
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
