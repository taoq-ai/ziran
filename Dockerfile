FROM python:3.12-slim
WORKDIR /app
# .git is not copied, so hatch-vcs takes the version from this build arg
ARG ZIRAN_VERSION=0+unknown
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY ziran/ ./ziran/
RUN SETUPTOOLS_SCM_PRETEND_VERSION=${ZIRAN_VERSION} pip install --no-cache-dir .
ENTRYPOINT ["ziran"]
