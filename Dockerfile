# Use an existing docker image as a base
FROM python:3.9-buster

RUN apt-get update && apt-get install wait-for-it

# Set environment varibles
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

#Change working directory
WORKDIR /app

# COPY requirements.txt
COPY ./requirements.txt ./

RUN pip install -r requirements.txt 
# Copy main.py file
COPY ./app ./

# Create a folder
RUN mkdir -p ./uploaded

EXPOSE 5000
# Tell what to do when it starts as a container
# CMD ["gunicorn","app:app","--bind","0.0.0.0:5000", "--workers", "4"]
CMD ["/bin/bash", "entrypoint.sh"]