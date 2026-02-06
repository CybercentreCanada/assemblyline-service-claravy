ARG branch=latest
ARG version=1.0.0.dev1

# Prepare build image
FROM cccs/assemblyline-v4-service-base:$branch AS build
ARG version

USER root
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential libfuzzy-dev

COPY . .

RUN pip wheel -w ./build .
RUN cd ./build && rm assemblyline_service_claravysvc-*

# Prepare runtime image
FROM cccs/assemblyline-v4-service-base:$branch
ARG version

# Python path to the service class from your service directory
ENV SERVICE_PATH=claravysvc.claravysvc.ClaravySvc

# Install apt dependencies
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Install python dependencies
USER assemblyline
COPY requirements.txt requirements.txt
RUN pip install \
    --no-cache-dir \
    --user \
    --requirement requirements.txt && \
    rm -rf ~/.cache/pip

# Copy service code
WORKDIR /opt/al_service
COPY . .

COPY --from=build /app/build ./build
RUN pip install --no-cache-dir ./build/*.whl
RUN pip install -e .

# Patch version in manifest
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml
RUN rm -rf ./build/

USER assemblyline
