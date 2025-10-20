/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
pipeline {
  agent any

  tools {
    maven 'maven_3_latest'
    jdk params.jdkVersion
  }

  options {
      // Configure an overall timeout for the build of ten hours.
      timeout(time: 20, unit: 'HOURS')
      // When we have test-fails e.g. we don't need to run the remaining steps
      buildDiscarder(logRotator(numToKeepStr: '5', artifactNumToKeepStr: '5'))
  }

  parameters {
      choice(name: 'nodeLabel', choices: ['ubuntu', 'arm', 'Windows'])
      choice(name: 'jdkVersion', choices: ['jdk_17_latest', 'jdk_21_latest', 'jdk_25_latest', 'jdk_26_latest', 'jdk_17_latest_windows', 'jdk_21_latest_windows', 'jdk_25_latest_windows'])
      booleanParam(name: 'deployEnabled', defaultValue: true)
      booleanParam(name: 'sonarEnabled', defaultValue: true)
      booleanParam(name: 'testsEnabled', defaultValue: true)
  }

  triggers {
    cron('@weekly')
    pollSCM('@daily')
  }

  stages {
    stage('Initialization') {
      steps {
        echo "running on ${env.NODE_NAME}"
        echo 'Building branch ' + env.BRANCH_NAME
        echo 'Using PATH ' + env.PATH
      }
    }

    stage('Cleanup') {
      steps {
        echo 'Cleaning up the workspace'
        deleteDir()
      }
    }

    stage('Checkout') {
      steps {
        echo 'Checking out branch ' + env.BRANCH_NAME
        checkout scm
      }
    }

    stage('Build JDK 17 Linux') {
      tools {
        jdk "jdk_17_latest"
      }
      steps {
        echo 'Building JDK 17 Linux'
        sh 'java -version'
        sh 'mvn -version'
        sh 'mvn clean install'
      }
    }

    stage('Build JDK 21 Linux') {
      tools {
        jdk "jdk_21_latest"
      }
      steps {
        echo 'Building JDK 21 Linux'
        sh 'java -version'
        sh 'mvn -version'
        sh 'mvn clean install'
      }
    }

    stage('Build JDK 25 Linux') {
      tools {
        jdk "jdk_25_latest"
      }
      steps {
        echo 'Building JDK 25 Linux'
        sh 'java -version'
        sh 'mvn -version'
        sh 'mvn clean install'
      }
    }
  }
}
