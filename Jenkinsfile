@Library('infra-jenkins@master') _

stage('checkout') {
  node('infra') {
    try {
      checkout scm
    } catch (e) {
      echo e.getMessage()
      currentBuild.result = 'FAILURE'
    }
  }
}

stage('compile') {
  if (currentBuild.result != 'FAILURE') {
    node('infra') {
      try {
        docker.image('golang:latest').inside('-u 0:0') {
          sh '''
            WORKSPACE=`pwd`
            mkdir /go/src/powerdns_exporter
            mv * /go/src/powerdns_exporter
            cd /go/src/powerdns_exporter
            go get
            go build
            mv /go/bin/powerdns_exporter $WORKSPACE
          '''
        }
      } catch (e) {
        echo e.getMessage()
        currentBuild.result = 'FAILURE'
      }
    }
  }
}

stage('upload') {
  if (currentBuild.result != 'FAILURE') {
    if (env.BRANCH_NAME == 'master') {
      node('infra') {
        try {
          sendToNexus("infra-powerdns-exporter", "powerdns_exporter", ".")
        } catch (e) {
          echo e.getMessage()
          currentBuild.result = 'FAILURE'
        }
      }
    } else {
      echo "Skipping, not master branch"
    }
  }
}

stage('cleanup') {
  node('infra') {
    step([$class: 'WsCleanup'])
  }
}
