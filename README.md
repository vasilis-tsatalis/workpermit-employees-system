# workpermit-employees-system
Workpermit Management System for Employees

# Download and run the application local enter Github copy the url https://github.com/vasilis-tsatalis/workpermit-employees-system.git
$ git clone https://github.com/vasilis-tsatalis/workpermit-employees-system.git

# Docker Compose - Build and Execute
$ docker-compose up --build

# Enter running container
$ docker ps
$ docker exec -it <"container_id"> bash

# Stop docker container
$ docker ps
$ docker container stop <"container_id">

# Push image to container in Google Cloud Platform
$ docker tag flask-image gcr.io/<"project-id">/my-flask-app

# Application Login
# By running the a default admin user will be created
- Username: administrator Password: password

# Check Mail Server UI on localhost, open a browser "http://localhost:8025"


# Deploy the project to a kubernetes cluster

## create secrets files for database and web application
$ kubectl create secret generic pg-user \
--from-literal=POSTGRES_USER='<username>' --from-literal=POSTGRES_PASSWORD='<password>'

$ kubectl create secret generic flask-app --from-literal=DB_URL=postgresql://admin_dev:dev2021@localhost:5432/db-ergasia-test \ --from-literal=SECRET_KEY='<key>' \
--from-literal=ADMIN_USERNAME='<username>' --from-literal=ADMIN_EMAIL='<test@email.com>' --from-literal=ADMIN_PASS='<password>'

## persistent volumes
$ kubectl apply -f k8s/db/postgres-pvc.yml

## deployments
$ kubectl apply -f k8s/db/postgres-deployment.yml
$ kubectl apply -f k8s/flask/flask-deployment.yml
$ kubectl apply -f k8s/mail/mail-deployment.yml

## services
$ kubectl apply -f k8s/db/postgres-clip.yml
$ kubectl apply -f k8s/flask/flask-clip.yml
$ kubectl apply -f k8s/mail/mail-clip.yml

## ingress
$ kubectl apply -f k8s/ingress/flask-ingress-.yml # for http
$ kubectl apply -f k8s/ingress/flask-ingress-ssl.yml # for https
