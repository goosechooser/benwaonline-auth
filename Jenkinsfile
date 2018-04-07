pipeline {
    agent any
    stages {
        stage('Build image') {
            steps {
                sh 'mkdir work_dir'
                sh 'docker-compose build testing'
            }
        }

        stage('Test image') {
            steps {
                sh 'docker run --name memcached -d -p 11211 --network=jenkins-testing memcached'
                sh 'docker-compose run testing'
                sh 'sed "s/\\/testing\\///" work_dir/coverage.xml > coverage.xml'
                step([$class: 'CoberturaPublisher', autoUpdateHealth: false,
                autoUpdateStability: false, coberturaReportFile: 'coverage.xml',
                failNoReports: false, failUnhealthy: false, failUnstable: false,
                maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
            }
        }

    }
    post {
        always {
            sh 'docker rm --force memcached'
            sh 'rm -rf work_dir'
        }
        success {
            echo 'I succeeeded!'
        }
        unstable {
            echo 'I am unstable :/'
        }
        failure {
            echo 'I failed :('
        }
        changed {
            echo 'Things were different before...'
        }
    }
}
