#!/usr/bin/env groovy

@Library("pipelineAutomationLib")_

Map config = [:]

// Example test run command:
// test/test-openbao-container.sh \
//    --skip-build \
//    --image-base 'openbao-ansible' \
//    --test-results-dir '.test-results' \
//    --build-id 'build-2961'
//
// List testCmdList = []
// testCmdList.push("test/test-openbao-container.sh")
// testCmdList.push("--skip-build")
// testCmdList.push("--image-base openbao-ansible")
// testCmdList.push("--test-results-dir '.test-results'")
//
// String testCmd = testCmdList.join(' ')
//
// config.buildTestAppendIdArg = true
// config.buildTestAppendIdOption = "--build-id"
//
// config.buildTestCommand = testCmd
//

buildDockerManifest(config)
