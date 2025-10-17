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
  agent none
  options {
    buildDiscarder(logRotator(numToKeepStr: '10'))
    timeout(time: 8, unit: 'HOURS')
  }
  triggers {
    cron('@weekly')
    pollSCM('@daily')
  }
  stages {
    stage ('Debug') {
      options {
        timeout(time: 1, unit: 'HOURS')
        retry(2)
      }
      agent {
        docker {
          label 'ubuntu'
          image 'apachedirectory/maven-build:jdk-11'
          alwaysPull true
          args '-v $HOME/.m2:/home/hnelson/.m2'
        }
      }
      steps {
        sh 'env'
      }
      post {
        always {
          deleteDir()
        }
      }
    }
    stage ('Build and Test') {
      parallel {
        stage ('Linux Java 17') {
          options {
            timeout(time: 4, unit: 'HOURS')
            retry(2)
          }
          agent {
            docker {
              label 'ubuntu'
              image 'apachedirectory/maven-build:jdk-17'
              alwaysPull true
              args '-v $HOME/.m2:/home/hnelson/.m2'
            }
          }
          steps {
            sh 'mvn -U -V clean verify'
          }
          post {
            always {
              deleteDir()
            }
          }
        }
        stage ('Linux Java 21') {
          options {
            timeout(time: 4, unit: 'HOURS')
            retry(2)
          }
          agent {
            docker {
              label 'ubuntu'
              image 'apachedirectory/maven-build:jdk-21'
              alwaysPull true
              args '-v $HOME/.m2:/home/hnelson/.m2'
            }
          }
          steps {
            sh 'mvn -U -V clean verify'
          }
          post {
            always {
              deleteDir()
            }
          }
        }
        stage ('Linux Java 25') {
          options {
            timeout(time: 4, unit: 'HOURS')
            retry(2)
          }
          agent {
            docker {
              label 'ubuntu'
              image 'apachedirectory/maven-build:jdk-25'
              alwaysPull true
              args '-v $HOME/.m2:/home/hnelson/.m2'
            }
          }
          steps {
            sh 'mvn -U -V clean verify'
          }
          post {
            always {
              deleteDir()
            }
          }
        }
        stage ('Windows Java 17') {
          options {
            timeout(time: 4, unit: 'HOURS')
            retry(2)
          }
          agent {
            label 'Windows'
          }
          steps {
            bat '''
            set JAVA_HOME=F:\\jenkins\\tools\\java\\latest17
            set MAVEN_OPTS="-Xmx512m"
            F:\\jenkins\\tools\\maven\\latest3\\bin\\mvn -U -V clean verify
            '''
          }
          post {
            always {
              deleteDir()
            }
          }
        }
        stage ('Windows Java 21') {
          options {
            timeout(time: 4, unit: 'HOURS')
            retry(2)
          }
          agent {
            label 'Windows'
          }
          steps {
            bat '''
            set JAVA_HOME=F:\\jenkins\\tools\\java\\latest21
            set MAVEN_OPTS="-Xmx512m"
            F:\\jenkins\\tools\\maven\\latest3\\bin\\mvn -U -V clean verify
            '''
          }
          post {
            always {
              deleteDir()
            }
          }
        }/*
        stage ('Windows Java 25') {
          options {
            timeout(time: 4, unit: 'HOURS')
            retry(2)
          }
          agent {
            label 'Windows'
          }
          steps {
            bat '''
            set JAVA_HOME=F:\\jenkins\\tools\\java\\latest25
            set MAVEN_OPTS="-Xmx512m"
            F:\\jenkins\\tools\\maven\\latest3\\bin\\mvn -U -V clean verify
            '''
          }
          post {
            always {
              deleteDir()
            }
          }
        }*/
      }
    }
    stage ('Deploy') {
      options {
        timeout(time: 2, unit: 'HOURS')
        retry(2)
      }
      agent {
        label 'ubuntu && !H28 && !H36 && !H40'
      }
      // https://cwiki.apache.org/confluence/display/INFRA/JDK+Installation+Matrix
      // https://cwiki.apache.org/confluence/display/INFRA/Maven+Installation+Matrix
      steps {
        sh '''
        export JAVA_HOME=/home/jenkins/tools/java/latest1.8
        export MAVEN_OPTS="-Xmx512m"
        /home/jenkins/tools/maven/latest3/bin/mvn -U -V clean deploy -DskipTests
        '''
      }
      post {
        always {
          deleteDir()
        }
      }
    }
  }
  post {
    failure {
      mail to: 'notifications@directory.apache.org',
      subject: "Jenkins pipeline failed: ${currentBuild.fullDisplayName}",
      body: "Jenkins build URL: ${env.BUILD_URL}"
    }
    fixed {
      mail to: 'notifications@directory.apache.org',
      subject: "Jenkins pipeline fixed: ${currentBuild.fullDisplayName}",
      body: "Jenkins build URL: ${env.BUILD_URL}"
    }
  }
}

