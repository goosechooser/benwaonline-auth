FROM python:3.6 as packages
COPY requirements.txt .
RUN pip wheel -r requirements.txt --wheel-dir=/tmp/wheelhouse

FROM python:3.6 as testing
COPY --from=packages /tmp/wheelhouse /tmp/wheelhouse

COPY . /testing/
WORKDIR /testing
RUN mkdir reports

RUN pip install -r requirements.txt --find-links=/tmp/wheelhouse .
RUN pip install -r requirements-testing.txt
RUN find . -name "*.pyc" -delete

FROM python:3.6
COPY --from=packages /tmp/wheelhouse /tmp/wheelhouse

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY . .
RUN pip install -r requirements.txt --find-links=/tmp/wheelhouse .