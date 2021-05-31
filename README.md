# workpermit-employees-system
Workpermit Management System for Employees

# Docker (build-run)
$ docker build -t my-flask-app .
$ docker run -p 8000:5000 my-flask-app

# Docker Compose
$ docker-compose up --build

# Push image to container in Google Cloud Platform
$ docker tag flask-image gcr.io/<project-id>/my-flask-app
