# The tools the backup and sqlite-db containers need, installed once when
# the image is built. They used to be installed with `apk add` every time
# the container started, which needs the internet: a Mac that booted
# without a connection left the backup container crash-looping, and no
# backups were taken until it came back.
FROM alpine:3.24
RUN apk add --no-cache sqlite dcron tzdata
