# workpermit-employees-system
Workpermit Management System for Employees

# Download and run the application local enter Github 
# and copy the url https://github.com/vasilis-tsatalis/workpermit-employees-system.git
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
# Username: administrator Password: password

# Check Mail Server UI on localhost 
# Open a browser "http://localhost:8025"