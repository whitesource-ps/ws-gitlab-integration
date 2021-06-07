![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
![Docker Image Version (latest by date)](https://img.shields.io/docker/v/whitesourcetools/ws-gl-int)
  
# WhiteSource GitLab Integration
WhiteSource lightweight Integration to populate Security and License data from WhiteSource Into GitLab 

## Prerequisites
- GitLab Ultimate
- Auto DevOps enabled 

## Usage
1. For each project define **WS_PROJ_TOKEN** and **WS_USER_KEY** variables in Projects's _Settings -> CI/CD -> Variables_ where:
   * WS_PROJ_TOKEN - WhiteSource Project Token.
   * WS_USER_KEY - WhiteSource User Key.
1. Create GitLab pipeline job that consists:
```shell
include:
  - template: License-Scanning.gitlab-ci.yml

license_scanning:
  image:
    name: "docker.io/whitesourcetools/ws-gl-int:latest"
  script:
    - python3 /opt/ws_gl_int/gitlab_integration/ws2gl_format_convertor.py -k $WS_PROJ_TOKEN -u $WS_USER_KEY -t license -o $CI_PROJECT_DIR/

dependency_scanning:
  image:
    name: docker.io/whitesourcetools/ws-gl-int:latest
    entrypoint: [""]
  script:
    - python3 /opt/ws_gl_int/gitlab_integration/ws2gl_format_convertor.py -k $WS_PROJ_TOKEN -u $WS_USER_KEY -t dependency -o $CI_PROJECT_DIR/
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json

```